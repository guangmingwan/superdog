{
"targets": [
    {
      "target_name": "superdog",
      "conditions": [
         ['OS=="win"',{
	   "sources": [ "src/superdog.cc" ],
           "libraries": [
             "-llegacy_stdio_definitions.lib",
             "../vendor/libdog_windows_demo.lib"
           ]
         }
         ],
	
        ['OS=="mac"', {
          "sources": ["src/superdog_mac.cc"],
          "link_settings": {
          }
        }]
        ]
      
    },
  ]
}
