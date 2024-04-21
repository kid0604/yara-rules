import "pe"

rule sig_17333_Updater
{
	meta:
		description = "17333 - file Updater.vbs"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "be0e75d50565506baa1ce24301b702989ebe244b3a1d248ee5ea499ba812d698"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "objShell.Run (Base64Decode(xxx)), 0, False" fullword ascii
		$s2 = "oNode.DataType = \"bin.base64\"" fullword ascii
		$s3 = "BinaryStream.Open" fullword ascii
		$s4 = "BinaryStream.Position = 0" fullword ascii
		$s5 = "BinaryStream.Type = adTypeBinary" fullword ascii
		$s6 = "BinaryStream.Type = adTypeText" fullword ascii
		$s7 = "Stream_BinaryToString = BinaryStream.ReadText" fullword ascii
		$s8 = "BinaryStream.CharSet = \"us-ascii\"" fullword ascii
		$s9 = "BinaryStream.Write Binary" fullword ascii
		$s10 = "Base64Decode = Stream_BinaryToString(oNode.nodeTypedValue)" fullword ascii
		$s11 = "oNode.text = vCode" fullword ascii
		$s12 = "Set BinaryStream = Nothing" fullword ascii
		$s13 = "Set BinaryStream = CreateObject(\"ADODB.Stream\")" fullword ascii
		$s14 = "Const adTypeBinary = 1" fullword ascii
		$s15 = "Private Function Stream_BinaryToString(Binary)" fullword ascii
		$s16 = "Function Base64Decode(ByVal vCode)" fullword ascii
		$s17 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
		$s18 = "xxx = \"cG93ZXJz@GVsbC5leGUgLUV4ZWMgQnlwYXNzIEM6XFVzZXJzXE5hb21pLktpcmtsYW5kXEFwcERhdGFcTG9jYWxcTWljcm9zb2Z0XFdpbmRvd3NcVXBkYXRl" ascii
		$s19 = "Set oNode = oXML.CreateElement(\"base64\")" fullword ascii
		$s20 = "Set oNode = Nothing" fullword ascii

	condition:
		uint16(0)==0x7878 and filesize <3KB and 8 of them
}
