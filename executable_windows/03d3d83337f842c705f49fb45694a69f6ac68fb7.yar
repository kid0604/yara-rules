rule Agenttesla_type1
{
	meta:
		description = "detect Agenttesla in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		os = "windows"
		filetype = "executable"

	strings:
		$iestr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\IELibrary\\\\IELibrary\\\\obj\\\\Debug\\\\IELibrary.pdb"
		$atstr = "C:\\\\Users\\\\Admin\\\\Desktop\\\\ConsoleApp1\\\\ConsoleApp1\\\\obj\\\\Debug\\\\ConsoleApp1.pdb"
		$sqlitestr = "Not a valid SQLite 3 Database File" wide

	condition:
		all of them
}
