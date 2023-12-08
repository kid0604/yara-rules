import "pe"
import "math"

rule FscanRule5
{
	meta:
		description = "Detect the risk of Malware Fscan Rule 5"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Invalid field. Cannot determine length.Unable to find tree path for disconnectchain is not signed by an acceptable CAcipher: inc" ascii
		$x2 = "VirtualQuery for stack base failedadding nil Certificate to CertPoolarray of non-uint8 in field %d: %Tbad scalar length: %d, exp" ascii
		$x3 = "slice bounds out of range [:%x] with length %ysql/driver: couldn't convert %d into type boolsql/driver: couldn't convert %q into" ascii
		$x4 = " > (den<<shift)/2string_data_right_truncationunexpected %q after error %sunexpected Parse response %qunexpected end of JSON inpu" ascii
		$x5 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=proxy-connectionreflect mismatchregexp: Compile(remote I/O error" ascii
		$x6 = ".lib section in a.out corrupted11368683772161602973937988281255684341886080801486968994140625CLIENT_HANDSHAKE_TRAFFIC_SECRETCent" ascii
		$x7 = "ssh: unexpected packet in response to channel open: %Ttls: certificate used with invalid signature algorithmtls: found unknown p" ascii
		$x8 = "Caucasus Standard TimeClosing TCP connectionConvertSidToStringSidWConvertStringSidToSidWCreateEnvironmentBlockCreateIoCompletion" ascii
		$x9 = "Belarus Standard TimeCentral Standard TimeCommand unrecognized.Eastern Standard TimeGSSAPI protocol errorGetProfilesDirectoryWIn" ascii
		$x10 = "http: RoundTripper implementation (%T) returned a nil *Response with a nil errortls: either ServerName or InsecureSkipVerify mus" ascii
		$x11 = "driver.ErrBadConn in checkBadConn. This should not happen.http2: client connection force closed via ClientConn.Closejson: cannot" ascii
		$x12 = "Failed to send CommitXact with %vGODEBUG: no value specified for \"Sending NegotiateProtocol requestbad point length: %d, expect" ascii
		$x13 = "lock: lock countslice bounds out of rangeslice of unsupported typesocket type not supportedssh: handshake failed: %vssh: padding" ascii
		$x14 = "http2: Transport conn %p received error from processing frame %v: %vhttp2: Transport received unsolicited DATA frame; closing co" ascii
		$x15 = "entersyscallexit status failoverportgcBitsArenasgcpacertracegetaddrinfowgot token %vhmac-sha1-96host is downhttp2debug=1http2deb" ascii
		$x16 = "INSERTBULKINT2VECTORIP addressKEEP_NULLSKeep-AliveKharoshthiLockFileExManichaeanMessage-IdNo ContentOld_ItalicOld_PermicOld_Turk" ascii
		$x17 = "[*]Not ExtendedNot ModifiedOPTS UTF8 ONPG_ATTRIBUTEPG_NODE_TREEPUSH_PROMISEPahawh_HmongRCodeRefusedRCodeSuccessREGNAMESPACEREGPR" ascii
		$x18 = "streamSafe was not resetstructure needs cleaningtext/html; charset=utf-8unexpected ReadyForQueryunexpected buffer len=%vunknown " ascii
		$x19 = "span set block with unpopped elements found in resetssh: peer's curve25519 public value has wrong lengthssh: unexpected message " ascii
		$x20 = "file descriptor in bad statefindrunnable: netpoll with pfound pointer to free objectgcstopm: negative nmspinninggeneral SOCKS se" ascii

	condition:
		uint16(0)==0x5a4d and filesize <30000KB and 3 of ($x*)
}
