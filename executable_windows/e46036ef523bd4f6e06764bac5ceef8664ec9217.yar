rule Windows_Ransomware_Hive_3ed67fe6
{
	meta:
		author = "Elastic Security"
		id = "3ed67fe6-6347-4aef-898d-4cb267bcbfc7"
		fingerprint = "a15acde0841f08fc44fdc1fea01c140e9e8af6275a65bec4a7b762494c9e6185"
		creation_date = "2021-08-26"
		last_modified = "2022-01-13"
		threat_name = "Windows.Ransomware.Hive"
		reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hive"
		filetype = "executable"

	strings:
		$a1 = "bmr|sql|oracle|postgres|redis|vss|backup|sstp"
		$a2 = "key.hive"
		$a3 = "Killing processes"
		$a4 = "Stopping services"
		$a5 = "Removing itself"

	condition:
		all of them
}
