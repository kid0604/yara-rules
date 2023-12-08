import "pe"
import "math"

rule FrpRule1
{
	meta:
		description = "Detect the risk of Malware Frp Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "casgstatus: waiting for Gwaiting but is Grunnablechacha20poly1305: bad nonce length passed to Openchacha20poly1305: bad nonce le" ascii
		$x2 = "Unexpected argument to `immutable`VirtualQuery for stack base failed^((\\d{4}-)?\\d{3}-\\d{3}(-\\d{1})?)?$adding nil Certificate" ascii
		$x3 = "28421709430404007434844970703125: day-of-year does not match dayAssociate to %v blocked by rulesCertAddCertificateContextToStore" ascii
		$x4 = "webpackJsonp([0],[function(e,t,o){var r=o(159);\"string\"==typeof r&&(r=[[e.i,r,\"\"]]);var n={hmr:!0};n.transform=void 0,n.inse" ascii
		$x5 = " 2020 Denis Pushkarev (zloirock.ru)\"})},function(e,t){var o=Math.ceil,r=Math.floor;e.exports=function(e){return isNaN(e=+e)?0:(" ascii
		$x6 = "target must be an absolute URL or an absolute path: %qtls: certificate used with invalid signature algorithmtls: client indicate" ascii
		$x7 = "entersyscallexcludesrunefloat32Slicefloat64SlicegcBitsArenasgcpacertracegetaddrinfowhost is downhtml_encodedhttp2debug=1http2deb" ascii
		$x8 = "Go pointer stored into non-Go memoryHeader called after Handler finishedHijack failed on protocol switch: %vIA5String contains i" ascii
		$x9 = " because it doesn't contain any IP SANs2006-01-02 15:04:05.999999999 -0700 MST277555756156289135105907917022705078125Bad param n" ascii
		$x10 = "Subject: AMDisbetter!AuthenticAMDBidi_ControlCIDR addressCONTINUATIONCentaurHaulsCoCreateGuidContent TypeContent-TypeCookie.Valu" ascii
		$x11 = "Simply type handle tcp work connection, use_encryption: %t, use_compression: %treconstruction required as one or more required d" ascii
		$x12 = "Unexpected argument to `proxy-revalidate`WriteHeader called after Handler finished[ERR] yamux: Invalid protocol version: %dasn1:" ascii
		$x13 = "getenv before env initgzip: invalid checksumheadTailIndex overflowheader field %q = %q%shpack: string too longhttp2: frame too l" ascii
		$x15 = "InitiateSystemShutdownExWIsValidSecurityDescriptorKaliningrad Standard TimeMiddle East Standard TimeNew Zealand Standard TimeNor" ascii
		$x16 = ".WithDeadline(.in-addr.arpa.127.0.0.1:70001907348632812595367431640625: extra text: <not Stringer>Accept-CharsetCertCloseStoreCo" ascii
		$x17 = "flate: internal error: function %q not definedgarbage collection scangcDrain phase incorrectgo with non-empty framehttp2: handle" ascii
		$x18 = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-3[0-9a-fA-F]{3}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$x509: signature check attempts limit reached while" ascii
		$x19 = "non-IPv4 addressnon-IPv6 addressobject is remotepacer: H_m_prev=plugin_http_userplugin_unix_pathproxy-connectionquoted-printable" ascii
		$x20 = "span set block with unpopped elements found in resettls: internal error: session ticket keys unavailabletls: private key type do" ascii

	condition:
		uint16(0)==0x5a4d and filesize <32000KB and 6 of ($x*)
}
