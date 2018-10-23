{
"targets": [
    {
      "target_name": "superdog",
      "sources": [ "src/superdog.cc" ],
      "conditions": [
         ['OS=="win"',{
           "libraries": [
             "-llegacy_stdio_definitions.lib",
             "../vendor/libdog_windows_demo.lib"
           ]
         },{
           "type":"none"
         }]
      ]
    },
  ]
}
