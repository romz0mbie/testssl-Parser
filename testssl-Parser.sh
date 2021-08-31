#!/bin/bash

######################## testssl.sh Parser ########################
#
# Created by romz0mbie: https://github.com/romz0mbie
#
# A very, VERY crudely thrown together script to parse
# out the results from testssl.sh.
#
# If you do not have testssl.sh, please download it
# from GitHub: https://github.com/drwetter/testssl.sh
#
# Thanks to drwetter for saving us all a lot of time
# and headaches by making testssl.sh
#
###################################################################

######## Checks Performed by testssl.sh ########


        ###Testing Protocols###
        #
        # SSLv2 - Parsed
        # SSLv3 - Parsed
        # TLS1 - Parsed
        # TLS1.1 - Parsed
        # TLS1.2
        # TLS1.3
        # NPN/SPDY
        # ALPN/HTTP2
        #
        #######################

        ###Testing cipher categories###
        #
        # NULL ciphers - Parsed
        # Anonymous NULL Ciphers - Parsed
        # Export ciphers (w/o ADH+NULL) - Parsed
        # LOW: 64 Bit + DES, RC[2,4], MD5 (w/o export) - Parsed
        # Triple DES Ciphers / IDEA - Parsed
        # Obsoleted CBC ciphers (AES, ARIA etc.) - Parsed
        # Strong encryption (AEAD ciphers) with no FS - Parsed
        # Forward Secrecy strong encryption (AEAD ciphers) - Parsed
        #
        ###############################

        ###Testing server's cipher preferences###
        #
        # Has server cipher order? - Parsed
        # Negotiated protocol
        # Negotiated cipher
        #
        #########################################

        ###Testing robust forward secrecy (FS)###
        #
        # FS - Parsed
        # DH group offered - Parsed (Individual files for 768 & 1024)
        #
        #########################################

        ###Testing server defaults###
        #
        # TLS extensions (standard)
        # Session Ticket RFC 5077 hint
        # SSL Session ID support
        # Session Resumption
        # TLS clock skew
        # Client Authentication
        # Signature Algorithm  - Parsed (Individual files for SHA1 w/ RSA & MD5)
        # Server key size - Parsed (Individual files for 512 & 1024)
        # Server key usage
        # Server extended key usage
        # Serial / Fingerprints
        # Common Name (CN)
        # subjectAltName (SAN) - Parsed (Looks for Missing)
        # Trust (hostname) - Parsed
        # Chain of trust - Parsed (Individual files for Self Signed, Self Signed CA, and Chain Incomplete) 
        # EV cert (experimental)
        # Certificate Validity - Parsed (Individual files for < 30 Days, < 60 Days, and  Expired)
        # ETS/"eTLS", visibility info
        # Certificate Revocation List
        # OCSP URI - Parsed
        # OCSP stapling - Parsed
        # OCSP must staple extension
        # DNS CAA RR (experimental) - Parsed
        # Certificate Transparency
        # Certificates provided
        # Issuer
        # Intermediate Bad OCSP (exp.)
        #
        #############################

        ###Testing HTTP header response @ "/"###
        #
        # HTTP Status Code - Parsed
        # HTTP clock skew
        # Strict Transport Security - Parsed (Individual files for 'too short' and 'not offered')
        # Public Key Pinning
        # Server banner
        # Application banner
        # Cookie(s) - Parsed (Will group currently, working to parse individual files)
        # Security headers
        # Reverse Proxy banner
        #
        ########################################

        ###Testing vulnerabilities###
        #
        # Heartbleed (CVE-2014-0160) - Parsed
        # CCS (CVE-2014-0224) - Parsed
        # Ticketbleed (CVE-2016-9244) - Parsed
        # ROBOT - Parsed
        # Secure Renegotiation (RFC 5746) - Parsed
        # Secure Client-Initiated Renegotiation - Parsed
        # CRIME, TLS (CVE-2012-4929) - Parsed
        # BREACH (CVE-2013-3587) - Parsed
        # POODLE, SSL (CVE-2014-3566) - Parsed
        # TLS_FALLBACK_SCSV (RFC 7507) - Parsed
        # SWEET32 (CVE-2016-2183, CVE-2016-6329) - Parsed
        # FREAK (CVE-2015-0204) - Parsed
        # DROWN (CVE-2016-0800, CVE-2016-0703) - Parsed
        # LOGJAM (CVE-2015-4000) - Parsed (Individual files for 768 & 1024)
        # BEAST (CVE-2011-3389) - Parsed (Individual files for SSLv3 & TLSv1.0)
        # LUCKY13 (CVE-2013-0169) - Parsed
        # Winshock (CVE-2014-6321) - Parsed
        # RC4 (CVE-2013-2566, CVE-2015-2808) - Parsed
        #
        #############################

######Garbage code goes here######

###Intro###

echo
echo "######################### testssl.sh Parser #########################"
echo "#                                                                   #"
echo "# Created by romz0mbie: https://github.com/romz0mbie/testssl-Parser #"
echo "#                                                                   #"
echo "#####################################################################"
sleep 1
echo
echo "Creating testssl-Parser folder"
mkdir -p "testssl-Parser"
sleep 1
echo
echo "Folder created successfully"
sleep 1
echo

###/Intro###


###Parsing###

###Testing Protocols###
echo "Parsing Testing Protocols"
grep -d skip "SSLv2.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/SSLv2_Offered.txt
grep -d skip "SSLv3.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/SSLv3_Offered.txt
grep -d skip "TLS 1.*deprecated" * | grep -v "TLS 1.1" | tr _p : | cut -d "-" -f1 > testssl-Parser/TLSv1.0_Offered.txt
grep -d skip "TLS 1.1.*deprecated" * | tr _p : | cut -d "-" -f1 > testssl-Parser/TLSv1.1_Offered.txt
sleep 1
echo

###Testing Ciphers###
echo "Parsing Testing Ciphers"
grep -d skip "NULL ciphers.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/NULL_Ciphers_Offered.txt
grep -d skip "Anonymous NULL.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Anonymous_NULL_Ciphers_Offered.txt
grep -d skip "Export ciphers.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Export_Ciphers_Offered.txt
grep -d skip "LOW.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/LOW_Ciphers_Offered.txt
grep -d skip "Triple DES.*offered" * | grep -v "not" | tr _p : | cut -d "-" -f1 > testssl-Parser/3DES_IDEA_Ciphers_Offered.txt
grep -d skip "Obsoleted CBC.*offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Obsolete_CBC_Ciphers_Offered.txt
grep -d skip "Strong encryption.*not offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Strong_Encryption_no_FS_Not_Offered.txt
grep -d skip "Forward Secrecy strong.*not offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Forward_Secrecy_Strong_Encryption_Not_Offered.txt
sleep 1
echo

###Testing server's cipher preferences###
echo "Parsing Testing server's cipher preferences"
grep -d skip "cipher order.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/No_Server_Cipher_Order.txt
sleep 1
echo

###Testing robust forward secrecy (FS)###
echo "Parsing Testing robust forward secrecy (FS)"
grep -d skip "supporting Forward Secrecy" * | tr _p : | cut -d "-" -f1 > testssl-Parser/No_Ciphers_Supporting_FS_Offered.txt
grep -d skip "DH group offered.*1024" * | tr _p : | cut -d "-" -f1 > testssl-Parser/DH_Group_Offered_1024_bits.txt
grep -d skip "DH group offered.*768" * | tr _p : | cut -d "-" -f1 > testssl-Parser/DH_Group_Offered_768_bits.txt
sleep 1
echo

###Testing server defaults###
echo "Parsing Testing server defaults"
grep -d skip "Signature Algorithm.*SHA1 with RSA" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Signature_Algorithm_SHA1_with_RSA.txt
grep -d skip "Signature Algorithm.*MD5" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Signature_Algorithm_MD5.txt
grep -d skip "Server key size.*1024" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Server_Key_Size_1024_bits.txt
grep -d skip "Server key size.*512" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Server_Key_Size_512_bits.txt
grep -d skip "subjectAltName.*missing" * | tr _p : | cut -d "-" -f1 > testssl-Parser/subjectAltName_Missing.txt
grep -d skip "Trust.*certificate" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Certificate_does_not_match_supplied_URI.txt
grep -d skip "Chain of trust.*NOT.*self signed" * | grep -v "CA" | tr _p : | cut -d "-" -f1 > testssl-Parser/Chain_of_Trust_Self_Signed_Cert.txt
grep -d skip "Chain of trust.*NOT.*CA" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Chain_of_Trust_Self_Signed_CA.txt
grep -d skip "Chain of trust.*chain incomplete" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Chain_of_Trust_Incomplete.txt
grep -d skip "Certificate Validity.*expired" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Certificate_Expired.txt
grep -d skip "Certificate Validity.*expires < 60" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Certificate_Expiring_60_Days_or_less.txt
grep -d skip "CRL nor OCSP" * | tr _p : | cut -d "-" -f1 > testssl-Parser/CRL_nor_OCSP_URI_provided.txt
grep -d skip "OCSP stapling.*not offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/OSCP_Stapling_Not_Offered.txt
grep -d skip "DNS CAA RR.*not offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/DNS_CAA_RR_Not_Offered.txt
sleep 1
echo

###Testing HTTP header response @ "/"###
echo "Parsing Testing HTTP header response @ /"
grep -d skip "HTTP Status Code.*insecure" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Redirects_to_insecure_URL.txt
grep -d skip "Strict Transport Security.*not offered" * | tr _p : | cut -d "-" -f1 > testssl-Parser/STS_Not_Offered.txt
grep -d skip "Strict Transport Security.*too short" * | tr _p : | cut -d "-" -f1 > testssl-Parser/STS_Too_Short.txt
grep -d skip "Cookie.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Secure_Cookie_Flags_Missing.txt
sleep 1
echo

###Testing vulnerabilities###
echo "Parsing Testing vulnerabilities"
grep -d skip "Heartbleed.NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Heartbleed_CVE-2014-0160.txt
grep -d skip "CCS.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/CCS_CVE-2014-0224.txt
grep -d skip "Ticketbleed.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Ticketbleed_CVE-2016-9244.txt
grep -d skip "ROBOT.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/ROBOT.txt
grep -d skip "Secure Renegotiation.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Secure_Renegotiation-RFC_5746_Not_Supported.txt
grep -d skip "Client-Initiated.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Secure_Client-Initiated_Renegotiation-DoS_Threat.txt
grep -d skip "CRIME.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/CRIME_CVE-2012-4929.txt
grep -d skip "BREACH.*NOT" * | tr _p : | cut -d "-" -f1 > testssl-Parser/BREACH_CVE-2013-3587.txt
grep -d skip "POODLE.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/POODLE_CVE-2014-3566.txt
grep -d skip "TLS_FALLBACK_SCSV.*prevention NOT supported" * | tr _p : | cut -d "-" -f1 > testssl-Parser/TLS_FALLBACK_SCSV_RFC-7507.txt
grep -d skip "SWEET32.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/SWEET32_CVE-2016-2183_CVE-2016-6329.txt
grep -d skip "FREAK.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/FREAK_CVE-2015-0204.txt
grep -d skip "DROWN.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/DROWN_CVE-2016-0800_CVE-2016-0703.txt
grep -d skip "LOGJAM.*VULNERABLE.*768" * | tr _p : | cut -d "-" -f1 > testssl-Parser/LOGJAM_768_CVE-2015-4000.txt
grep -d skip "LOGJAM.*VULNERABLE.*1024" * | tr _p : | cut -d "-" -f1 > testssl-Parser/LOGJAM_1024_CVE-2015-4000.txt
grep -d skip "BEAST.*SSL3:" * | tr _p : | cut -d "-" -f1 > testssl-Parser/BEAST_SSL3_CVE-2011-3389.txt
grep -d skip "BEAST.*TLS1:" * | tr _p : | cut -d "-" -f1 > testssl-Parser/BEAST_TLS1_CVE-2011-3389.txt
grep -d skip "LUCKY13.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/LUCKY13_CVE-2013-0169.txt
grep -d skip "Winshock.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/Winshock_CVE-2014-6321.txt
grep -d skip "RC4.*VULNERABLE" * | tr _p : | cut -d "-" -f1 > testssl-Parser/RC4_CVE-2013-2566_CVE-2015-2808.txt
sleep 2
echo

###/Parsing####

echo "Parsing Complete"
echo
##END###
