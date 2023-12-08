rule INDICATOR_TOOL_SQLRecon
{
	meta:
		author = "ditekSHen"
		description = "Detects SQLRecon C# MS-SQL toolkit designed for offensive reconnaissance and post-exploitation"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "ConvertDLLToSQLBytes" ascii
		$s2 = "\\SQLRecon.pdb" ascii
		$s3 = "GetAllSQLServerInfo" ascii
		$s4 = "<GetMSSQLSPNs>b__" ascii
		$s5 = "select 1; exec master..xp_cmdshell" wide
		$s6 = "-> Command Execution" wide
		$s7 = ";EXEC dbo.sp_add_jobstep @job_name =" wide
		$s8 = "EXEC sp_drop_trusted_assembly 0x" wide
		$s9 = "(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))" wide

	condition:
		uint16(0)==0x5a4d and 5 of them
}
