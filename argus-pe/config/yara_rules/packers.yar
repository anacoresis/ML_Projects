rule UPX_Packer {
    meta:
        description = "Detects UPX executable packer signatures"
        severity = "HIGH"
    strings:
        $upx1 = "UPX0" ascii
        $upx2 = "UPX1" ascii
        $upx3 = "UPX!" ascii
    condition:
        any of ($upx*)
}

rule Hyperion_Packer {
    meta:
        description = "Detects Hyperion PE crypter/packer signatures"
        severity = "HIGH"
    strings:
        $hyp1 = ".hyperion" ascii lower
        $hyp2 = "Hyperion" ascii
    condition:
        any of ($hyp*)
}

rule Suspicious_Section_Names {
    meta:
        description = "Detects non-standard packed or obfuscated section names"
        severity = "MEDIUM"
    strings:
        $sec1 = ".packed" ascii
        $sec2 = ".themida" ascii
        $sec3 = ".vmp0" ascii
        $sec4 = ".aspack" ascii
    condition:
        any of ($sec*)
}
