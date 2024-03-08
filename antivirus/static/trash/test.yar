rule detect_a {
    strings:
        $a_string = "a"

    condition:
        $a_string
}