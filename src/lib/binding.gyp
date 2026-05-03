{
    "targets": [
        {
            "target_name": "bcrypt_core",
            "type": "static_library",
            "sources": [
                "../bcrypt/base64.cpp",
                "../bcrypt/bcrypt.cpp",
                "../bcrypt/blowfish.cpp"
            ],
            "cflags_cc": [ "-fexceptions" ],
            "include_dirs": [
                "../bcrypt/include"
            ],
            "direct_dependent_settings": {
                "include_dirs": [
                    "../bcrypt/include"
                ]
            }
        },
        {
            "target_name": "blf_v2",
            "cflags_cc": [ "-fexceptions" ],
            "sources": ["bcrypt.cpp"],
            "include_dirs": [
                "include"
            ],
            "dependencies": [
                "bcrypt_core"
            ]
        }
    ]
}