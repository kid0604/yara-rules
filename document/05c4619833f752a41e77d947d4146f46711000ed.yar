rule CryptoWall_Resume_phish : mail
{
	meta:
		Author = "http://phishme.com/"
		reference = "https://github.com/phishme/malware_analysis/blob/master/yara_rules/cryptowall.yar"
		description = "Detects phishing emails with malicious attachments pretending to be resumes"
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$hello2 = "my name is " nocase
		$file1 = "resume attached" nocase
		$file2 = "my resume is pdf file" nocase
		$file3 = "attached is my resume" nocase
		$sal1 = "I would appreciate your " nocase
		$sal2 = "I am looking forward to hearing from you" nocase
		$sal3 = "I look forward to your reply" nocase
		$sal4 = "Please message me back" nocase
		$sal5 = "our early reply will be appreciated" nocase
		$file4 = "attach is my resume" nocase
		$file5 = "PDF file is my resume" nocase
		$sal6 = "Looking forward to see your response" nocase

	condition:
		1 of ($hello*) and 1 of ($file*) and 1 of ($sal*)
}
