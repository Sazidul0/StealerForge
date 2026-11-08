import "pe"
import "math"

rule Stealer_Capability_DPAPI_and_SQLite {
    meta:
        description = "Detects DPAPI decryption and SQLite database harvesting typical of Chromium infostealers"
        severity = "high"
    strings:
        $dpapi1 = "CryptUnprotectData" ascii wide
        $dpapi2 = "BCryptDecrypt" ascii wide
        $dpapi3 = "os_crypt" ascii wide
        $dpapi4 = "encrypted_key" ascii wide
        
        $sql1 = "SELECT origin_url, username_value, password_value FROM logins" ascii wide nocase
        $sql2 = "SELECT host_key, name, encrypted_value FROM cookies" ascii wide nocase
        $sql3 = "sqlite3_open" ascii wide
        $sql4 = "sqlite3_prepare_v2" ascii wide
        $sql5 = "Login Data" ascii wide
        $sql6 = "Local State" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (1 of ($dpapi*)) and (2 of ($sql*))
}

rule Stealer_Crypto_Wallets_and_Messaging {
    meta:
        description = "Detects targeting of browser extension wallets, desktop crypto wallets, and Discord/Telegram tokens"
        severity = "high"
    strings:
        $ext_metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $ext_phantom  = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
        $ext_ronin    = "fnjhmkhhmkbjkkabndcnnogagogbneec" ascii wide
        $ext_tronlink = "ibnejdfjmmkpcnlpebklmnkoeoihofec" ascii wide
        
        $wal_exodus   = "\\Exodus\\exodus.wallet" ascii wide nocase
        $wal_electrum = "\\Electrum\\wallets" ascii wide nocase
        $wal_atomic   = "\\atomic\\Local Storage\\leveldb" ascii wide nocase
        
        $msg_discord  = "\\discord\\Local Storage\\leveldb" ascii wide nocase
        $msg_telegram = "\\Telegram Desktop\\tdata" ascii wide nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($ext_*) or 2 of ($wal_*) or 1 of ($msg_*))
}

rule Packer_High_Entropy_or_Hollowing_APIs {
    meta:
        description = "Flags packed outer loaders and process hollowing primitives"
        severity = "medium"
    strings:
        $inj1 = "NtUnmapViewOfSection" ascii wide
        $inj2 = "NtWriteVirtualMemory" ascii wide
        $inj3 = "ZwMapViewOfSection" ascii wide
        $inj4 = "SetThreadContext" ascii wide
        $inj5 = "VirtualAllocEx" ascii wide
    condition:
        uint16(0) == 0x5A4D and
        (
            3 of ($inj*) or
            for any i in (0..pe.number_of_sections - 1): (
                math.entropy(pe.sections[i].raw_data_offset, pe.sections[i].raw_data_size) >= 7.2
            )
        )
}
