rule Win_Ransomware_Locky
{
	meta:
		description = "Detect the risk of Ransomware Locky Rule 3"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 558bec518d45??50ff15[4]50ff15[4]85c074158b4d??83f9027c0dff7488fcff15[4]59c9c333c0c9c3 }
		$a1 = { 558bec5156578d45??50ff15[4]50ff15[4]8bf085f6741b837d??027c15ff7604ff15[4]59568bf8ff15[4]eb0233ff8bc75f5ec9c3 }
		$a2 = { 8d45??5068[4]c745??47657454c745??69636b43c745??6f756e74c645??00ff15[4]50ff15[4]8945??ffd0 }
		$a3 = { F51A5B38A8AF95760C8CF179CB43474580A5E48E2D74EF4E56660CA4A2A1407D }

	condition:
		any of them
}
