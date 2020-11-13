var { EIP_SCANNER } = require('./EIP_SCANNER');
//ip:Eip -Adpter IP Address
// scan:scan time (ms) 
//i_size input_size,o_size:output_size (byte)
// i_path, o_path:input ,output path
//readway:"readUInt16LE"  "readUInt16BE" 
//rgdb={},store response value
var rgdb={};
var clinet=new EIP_SCANNER(ip, scan, i_size, o_size, i_path, o_path,c_path,readway, {});
setInterval(() => {
    console.log(rgdb);  
}, 1000);
