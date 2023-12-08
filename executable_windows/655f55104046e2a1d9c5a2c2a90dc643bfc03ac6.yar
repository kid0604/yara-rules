rule PurpleFox_Dropper
{
	meta:
		id = "27j3DK8uiYjKigXCaoPUEK"
		fingerprint = "53c2af74e917254858409ea37d32e250656aa741800516020bdfff37732a3f51"
		version = "1.0"
		creation_date = "2021-11-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies PurpleFox aka DirtyMoe botnet, dropper CAB or MSI package."
		category = "MALWARE"
		malware_type = "DROPPER"
		os = "windows"
		filetype = "executable"

	strings:
		$doc = {D0 CF 11 E0}
		$cab = {4D 53 43 46}
		$s1 = "sysupdate.log" ascii wide
		$s2 = "winupdate32.log" ascii wide
		$s3 = "winupdate64.log" ascii wide

	condition:
		($doc at 0 and all of ($s*)) or ($cab at 0 and all of ($s*))
}
