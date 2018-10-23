const os = require('os');
const fs = require('fs');
const path = require('path');
var sourceLib = path.join( __dirname, "../vendor/libdog_windows_"+ os.arch() +"_demo.lib");
var targetLib = path.join( __dirname, "../vendor/libdog_windows_demo.lib");
fs.copyFileSync(sourceLib,targetLib);
console.log(`copy lib from  ${sourceLib} to ${targetLib} `);