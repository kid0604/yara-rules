rule Windows_Trojan_Generic_9997489c
{
	meta:
		author = "Elastic Security"
		id = "9997489c-4e22-4df1-90cb-dd098ca26505"
		fingerprint = "4c872be4e5eaf46c92e6f7d62ed0801992c36fee04ada1a1a3039890e2893d8c"
		creation_date = "2024-01-31"
		last_modified = "2024-02-08"
		threat_name = "Windows.Trojan.Generic"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic with specific strings"
		filetype = "executable"

	strings:
		$ldrload_dll = { 43 6A 45 9E }
		$loadlibraryw = { F1 2F 07 B7 }
		$ntallocatevirtualmemory = { EC B8 83 F7 }
		$ntcreatethreadex = { B0 CF 18 AF }
		$ntqueryinformationprocess = { C2 5D DC 8C }
		$ntprotectvirtualmemory = { 88 28 E9 50 }
		$ntreadvirtualmemory = { 03 81 28 A3 }
		$ntwritevirtualmemory = { 92 01 17 C3 }
		$rtladdvectoredexceptionhandler = { 89 6C F0 2D }
		$rtlallocateheap = { 5A 4C E9 3B }
		$rtlqueueworkitem = { 8E 02 92 AE }
		$virtualprotect = { 0D 50 57 E8 }

	condition:
		4 of them
}
