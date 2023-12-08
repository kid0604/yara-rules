import "math"

rule webshell_asp_runtime_compile
{
	meta:
		description = "Detect the risk of malicious file (aspwebsell)  Rule 41"
		os = "windows"
		filetype = "script"

	strings:
		$payload_reflection1 = "System.Reflection" nocase wide ascii
		$payload_reflection2 = "Assembly" fullword nocase wide ascii
		$payload_load_reflection1 = /[."']Load\b/ nocase wide ascii
		$payload_load_reflection2 = /\bGetMethod\(("load|\w)/ nocase wide ascii
		$payload_compile1 = "GenerateInMemory" nocase wide ascii
		$payload_compile2 = "CompileAssemblyFromSource" nocase wide ascii
		$payload_invoke1 = "Invoke" fullword nocase wide ascii
		$payload_invoke2 = "CreateInstance" fullword nocase wide ascii
		$rc_fp1 = "Request.MapPath"
		$rc_fp2 = "<body><mono:MonoSamplesHeader runat=\"server\"/>" wide ascii
		$asp_input1 = "request" fullword nocase wide ascii
		$asp_input2 = "Page_Load" fullword nocase wide ascii
		$asp_input3 = "UmVxdWVzdC5Gb3JtK" fullword wide ascii
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

	condition:
		filesize <10KB and ( any of ($asp_input*) or ($asp_xml_http and any of ($asp_xml_method*)) or ( any of ($asp_form*) and any of ($asp_text*) and $asp_asp)) and not any of ($rc_fp*) and (( all of ($payload_reflection*) and any of ($payload_load_reflection*)) or all of ($payload_compile*)) and any of ($payload_invoke*)
}
