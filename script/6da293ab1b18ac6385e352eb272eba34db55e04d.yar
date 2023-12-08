import "pe"

rule OilRig_Malware_Campaign_Gen1
{
	meta:
		description = "Detects malware from OilRig Campaign"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		hash1 = "d808f3109822c185f1d8e1bf7ef7781c219dc56f5906478651748f0ace489d34"
		hash2 = "80161dad1603b9a7c4a92a07b5c8bce214cf7a3df897b561732f9df7920ecb3e"
		hash3 = "662c53e69b66d62a4822e666031fd441bbdfa741e20d4511c6741ec3cb02475f"
		hash4 = "903b6d948c16dc92b69fe1de76cf64ab8377893770bf47c29bf91f3fd987f996"
		hash5 = "c4fbc723981fc94884f0f493cb8711fdc9da698980081d9b7c139fcffbe723da"
		hash6 = "57efb7596e6d9fd019b4dc4587ba33a40ab0ca09e14281d85716a253c5612ef4"
		hash7 = "1b2fee00d28782076178a63e669d2306c37ba0c417708d4dc1f751765c3f94e1"
		hash8 = "9f31a1908afb23a1029c079ee9ba8bdf0f4c815addbe8eac85b4163e02b5e777"
		hash9 = "0cd9857a3f626f8e0c07495a4799c59d502c4f3970642a76882e3ed68b790f8e"
		hash10 = "4b5112f0fb64825b879b01d686e8f4d43521252a3b4f4026c9d1d76d3f15b281"
		hash11 = "4e5b85ea68bf8f2306b6b931810ae38c8dff3679d78da1af2c91032c36380353"
		hash12 = "c3c17383f43184a29f49f166a92453a34be18e51935ddbf09576a60441440e51"
		hash13 = "f3856c7af3c9f84101f41a82e36fc81dfc18a8e9b424a3658b6ba7e3c99f54f2"
		hash14 = "0c64ab9b0c122b1903e8063e3c2c357cbbee99de07dc535e6c830a0472a71f39"
		hash15 = "d874f513a032ccb6a5e4f0cd55862b024ea0bee4de94ccf950b3dd894066065d"
		hash16 = "8ee628d46b8af20c4ba70a2fe8e2d4edca1980583171b71fe72455c6a52d15a9"
		hash17 = "55d0e12439b20dadb5868766a5200cbbe1a06053bf9e229cf6a852bfcf57d579"
		hash18 = "528d432952ef879496542bc62a5a4b6eee788f60f220426bd7f933fa2c58dc6b"
		hash19 = "93940b5e764f2f4a2d893bebef4bf1f7d63c4db856877020a5852a6647cb04a0"
		hash20 = "e2ec7fa60e654f5861e09bbe59d14d0973bd5727b83a2a03f1cecf1466dd87aa"
		hash21 = "9c0a33a5dc62933f17506f20e0258f877947bdcd15b091a597eac05d299b7471"
		hash22 = "a787c0e42608f9a69f718f6dca5556607be45ec77d17b07eb9ea1e0f7bb2e064"
		hash23 = "3772d473a2fe950959e1fd56c9a44ec48928f92522246f75f4b8cb134f4713ff"
		hash24 = "3986d54b00647b507b2afd708b7a1ce4c37027fb77d67c6bc3c20c3ac1a88ca4"
		hash25 = "f5a64de9087b138608ccf036b067d91a47302259269fb05b3349964ca4060e7e"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Get-Content $env:Public\\Libraries\\update.vbs) -replace" ascii
		$x2 = "wss.Run \"powershell.exe \" & Chr(34) & \"& {waitfor haha /T 2}\" & Chr(34), 0" fullword ascii
		$x3 = "Call Extract(UpdateVbs, wss.ExpandEnvironmentStrings(\"%PUBLIC%\") & \"\\Libraries\\update.vbs\")" fullword ascii
		$s4 = "CreateObject(\"WScript.Shell\").Run cmd, 0o" fullword ascii
		$b1 = "JGdsb2JhbDpteWhvc3QgP" ascii
		$b2 = "SE9NRT0iJXB1YmxpYyVcTGlicmFyaWVzX" ascii
		$b3 = "U2V0IHdzcyA9IENyZWF0ZU9iamVjdCgid1NjcmlwdC5TaGV" ascii
		$b4 = "JHNjcmlwdGRpciA9IFNwbGl0LVBhdGggLVBhcmVudCAtUGF0aCA" ascii
		$b5 = "DQpTZXQgd3NzID0gQ3JlYXRlT2JqZWN" ascii
		$b6 = "d2hvYW1pICYgaG9zdG5hb" ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <700KB and 1 of them )
}
