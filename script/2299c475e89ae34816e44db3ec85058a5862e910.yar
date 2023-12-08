rule HKTL_EXPL_POC_PY_SharePoint_CVE_2023_29357_Sep23_1
{
	meta:
		description = "Detects a Python POC to exploit CVE-2023-29357 on Microsoft SharePoint servers"
		author = "Florian Roth"
		reference = "https://github.com/Chocapikk/CVE-2023-29357"
		date = "2023-10-01"
		modified = "2023-10-01"
		score = 80
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "encoded_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=')"

	condition:
		filesize <30KB and $x1
}
