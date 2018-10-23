{
"targets": [
    {
      "target_name": "superdog",
      "sources": [ "src/superdog.cc" ],
      "conditions:": [
         ["OS=='win'",{
           "libraries": ["-lnode.lib"]
         }]
      ]
    },
  ]
}
