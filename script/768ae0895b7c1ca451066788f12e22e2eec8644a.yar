import "pe"

rule APT_Builder_PY_MATRYOSHKA_1
{
	meta:
		date_created = "2020-12-02"
		date_modified = "2020-12-02"
		md5 = "25a97f6dba87ef9906a62c1a305ee1dd"
		rev = 1
		author = "FireEye"
		description = "Yara rule for detecting APT Builder Python Matryoshka 1"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = ".pop(0)])"
		$s2 = "[1].replace('unsigned char buf[] = \"'"
		$s3 = "binascii.hexlify(f.read()).decode("
		$s4 = "os.system(\"cargo build {0} --bin {1}\".format("
		$s5 = "shutil.which('rustc')"
		$s6 = "~/.cargo/bin"
		$s7 = /[\x22\x27]\\\\x[\x22\x27]\.join\(\[\w{1,64}\[\w{1,64}:\w{1,64}[\x09\x20]{0,32}\+[\x09\x20]{0,32}2\]/

	condition:
		all of them
}
