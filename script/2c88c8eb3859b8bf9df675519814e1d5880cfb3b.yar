import "math"

rule WEBSHELL_ASP_Runtime_Compile : FILE
{
	meta:
		description = "ASP webshell compiling payload in memory at runtime, e.g. sharpyshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "https://github.com/antonioCoco/SharPyShell"
		date = "2021/01/11"
		modified = "2023-04-05"
		score = 75
		hash = "e826c4139282818d38dcccd35c7ae6857b1d1d01"
		hash = "e20e078d9fcbb209e3733a06ad21847c5c5f0e52"
		hash = "57f758137aa3a125e4af809789f3681d1b08ee5b"
		hash = "bd75ac9a1d1f6bcb9a2c82b13ea28c0238360b3a7be909b2ed19d3c96e519d3d"
		hash = "e44058dd1f08405e59d411d37d2ebc3253e2140385fa2023f9457474031b48ee"
		hash = "f6092ab5c8d491ae43c9e1838c5fd79480055033b081945d16ff0f1aaf25e6c7"
		hash = "dfd30139e66cba45b2ad679c357a1e2f565e6b3140a17e36e29a1e5839e87c5e"
		hash = "89eac7423dbf86eb0b443d8dd14252b4208e7462ac2971c99f257876388fccf2"
		hash = "8ce4eaf111c66c2e6c08a271d849204832713f8b66aceb5dadc293b818ccca9e"
		os = "windows"
		filetype = "script"

	strings:
		$payload_reflection1 = "System" fullword nocase wide ascii
		$payload_reflection2 = "Reflection" fullword nocase wide ascii
		$payload_reflection3 = "Assembly" fullword nocase wide ascii
		$payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
		$payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
		$payload_compile1 = "GenerateInMemory" nocase wide ascii
		$payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
		$payload_invoke1 = "Invoke" fullword nocase wide ascii
		$payload_invoke2 = "CreateInstance" fullword nocase wide ascii
		$payload_xamlreader1 = "XamlReader" fullword nocase wide ascii
		$payload_xamlreader2 = "Parse" fullword nocase wide ascii
		$payload_xamlreader3 = "assembly=" nocase wide ascii
		$payload_powershell1 = "PSObject" fullword nocase wide ascii
		$payload_powershell2 = "Invoke" fullword nocase wide ascii
		$payload_powershell3 = "CreateRunspace" fullword nocase wide ascii
		$rc_fp1 = "Request.MapPath"
		$rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
		$asp_input4 = "\\u0065\\u0071\\u0075" wide ascii
		$asp_input5 = "\\u0065\\u0073\\u0074" wide ascii
		$asp_xml_http = "Microsoft.XMLHTTP" fullword nocase wide ascii
		$asp_xml_method1 = "GET" fullword wide ascii
		$asp_xml_method2 = "POST" fullword wide ascii
		$asp_xml_method3 = "HEAD" fullword wide ascii
		$asp_form1 = "<form " wide ascii
		$asp_form2 = "<Form " wide ascii
		$asp_form3 = "<FORM " wide ascii
		$asp_asp = "<asp:" wide ascii
		$asp_text1 = ".text" wide ascii
		$asp_text2 = ".Text" wide ascii
		$sus_refl1 = " ^= " wide ascii
		$sus_refl2 = "SharPy" wide ascii

	condition:
		(( filesize <50KB and any of ($sus_refl*)) or filesize <10KB) and ( any of ($asp_input*) or ($asp_xml_http and any of ($asp_xml_method*)) or ( any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and not any of ($rc_fp*) and (( all of ($payload_reflection*) and any of ($payload_load_reflection*)) or ( all of ($payload_compile*) and any of ($payload_invoke*)) or all of ($payload_xamlreader*) or all of ($payload_powershell*))
}
