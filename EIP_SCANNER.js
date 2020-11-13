const { EthernetIP } = require("./ethernet-ip/");
const { encapsulation } = EthernetIP;
const { CPF } = encapsulation;
class EIP_SCANNER {
    constructor(host, cycle, i_size, o_size, i_path, o_path, c_path, readway = 'readUInt16LE', rgdb, ctrl = null) {
        this.rgdb = rgdb;
        this.host = host;
        this.readway = readway;
        this.cycle = cycle;
        this.i_size = i_size;
        this.i_path = i_path;
        this.o_size = o_size;
        this.o_path = o_path;
        this.c_path = c_path;
        this.t_o_id = 0;
        this.seq = 0;
        this.init();
        this.resdata = Buffer.alloc(this.o_size, 0);
        this.conADP();
        this.lidog = null;
        this.state = 0;
        setInterval(() => {

            if (this.state == 0) {
                setTimeout(() => {
                    this.conADP();
                }, 1000);
            }
        }, 5000);
    }
    init() {
        if (this.readway == "readUInt16LE" || this.readway == "readUInt16BE" || this.readway == "readInt16LE" || this.readway == "readInt16BE") {
            this.i_size = this.i_size * 2;
            this.o_size = this.o_size * 2;
        }


    }
    conADP() {
        let scope = this;
        this.client = null;
        this.client = new EthernetIP.ENIP();
        this.client.connect(scope.host).then(async () => {
            console.log('plc is connect!');
            this.state = 1;
            let tt = scope.ForwardOpen();
            scope.client.write(tt);

        }).catch(e => {
            console.log("eip-scanner connect error!");
            this.state = 0;
        })
        this.client.on("SendRRData Received", srrd => {
            if (srrd.length > 1) {
                if (srrd[1].TypeID == 178) {
                    scope.t_o_id = srrd[1].data.readUInt32LE(4);
                }
            }
        });

    }
    ForwardOpen(timeout = 10) {
        let scope = this;
        let data = scope.genFOdata();
        let timeoutBuf = Buffer.alloc(6);
        timeoutBuf.writeUInt32LE(0x00, 0); // Interface Handle ID (Shall be 0 for CIP)
        timeoutBuf.writeUInt16LE(timeout, 4); // Timeout (sec)
        let buf = CPF.build([
            { TypeID: CPF.ItemIDs.Null, data: Buffer.from([]) },
            { TypeID: CPF.ItemIDs.UCMM, data: data },
        ]);
        // Join Timeout Data with
        buf = Buffer.concat([timeoutBuf, buf]);

        // Build SendRRData Buffer
        return scope.headerbuild(0x6f, scope.client.state.session.id, buf);
    }
    headerbuild(cmd, session = 0x00, data = []) {
        // Validate requested command
        // if (!validateCommand(cmd)) throw new Error("Invalid Encapsulation Command!");

        const buf = Buffer.from(data);
        const send = {
            cmd: cmd,
            length: buf.length,
            session: session,
            status: 0x00,
            context: Buffer.alloc(8, 0x00),
            options: 0x00,
            data: buf
        };

        // Initialize header buffer to appropriate length
        let header = Buffer.alloc(24 + send.length);

        // Build header from encapsulation data
        header.writeUInt16LE(send.cmd, 0);
        header.writeUInt16LE(send.length, 2);
        header.writeUInt32LE(send.session, 4);
        header.writeUInt32LE(send.status, 8);
        send.context.copy(header, 12);
        header.writeUInt32LE(send.options, 20);
        send.data.copy(header, 24);

        return header;
    }

    genFOdata() {
        let scope = this;
        var fo_hd = Buffer.from([0x54, 0x2, 0x20, 0x06, 0x24, 0x01]); //open forwar cmd
        var fo_time = Buffer.from([0x0a, 0xf0]);
        var o_t_id = Buffer.alloc(4);
        o_t_id.writeUInt32LE(5000);// id:5000 o->t connection id
        var t_o_id = Buffer.alloc(4);
        t_o_id.writeUInt32LE(2000);// id:2000 t->o connection id
        var ser_num = Buffer.from([0x27, 0x17, 0xaa, 0, 0x53, 0x41, 0x4d, 0x50]);
        var c_timeout = Buffer.from([0x2, 0, 0, 0]);
        var rpi = Buffer.alloc(4);

        rpi.writeUInt32LE(scope.cycle * 1000);
        var con_o_para = Buffer.alloc(2);
        con_o_para.writeUInt8(0x48, 1); //连接参数 默认是o->t1对1,优先级2
        con_o_para.writeUInt8(scope.o_size + 6, 0);//
        var con_i_para = Buffer.alloc(2);
        con_i_para.writeUInt8(0x48, 1);//,t->o,1to1,opt=2,
        con_i_para.writeUInt8(scope.i_size + 2, 0);
        var trigger = Buffer.from([1]); //default cycle 
        var path_l = Buffer.from([9]);
        var ele_key_path = Buffer.from([0x34, 4, 0, 0, 0, 0, 0, 0, 0, 0]);
        var cl_path = Buffer.from([0x20, 4]);
        var con_path = Buffer.alloc(2);
        con_path.writeUInt8(0x24);
        con_path.writeUInt8(scope.c_path, 1);
        var o_path = Buffer.alloc(2);
        o_path.writeUInt8(0x2c);
        o_path.writeUInt8(scope.o_path, 1);
        var i_path = Buffer.alloc(2);
        i_path.writeUInt8(0x2c);
        i_path.writeUInt8(scope.i_path, 1);
        return Buffer.concat([fo_hd, fo_time, o_t_id, t_o_id, ser_num, c_timeout, rpi, con_o_para, rpi, con_i_para, trigger, path_l, ele_key_path, cl_path, con_path, o_path, i_path])

    }
    ioresponse() {
        clearTimeout(this.lidog);
        this.lidog = setTimeout(() => {
            this.state = 0;
        }, 3000);
        let scope = this;
        let idbuf = Buffer.alloc(4);
        idbuf.writeUInt32LE(this.t_o_id);
        let hseq = Buffer.alloc(4);
        var seq = 0;
        hseq.writeUInt32LE(this.seq);
        //	seq++;
        //	if(seq>0xfff0) seq=0;//use target same seq number
        let data1 = Buffer.concat([idbuf, hseq]);
        let hh = Buffer.alloc(4);
        let cipseq = Buffer.from([1, 0]);
        let hbuf = Buffer.from([1, 0, 0, 0]);
        let data2 = Buffer.concat([cipseq, hbuf, scope.resdata]);
        let buf = CPF.build([
            { TypeID: 0x8002, data: data1 },
            { TypeID: 0x00b1, data: data2 }
        ]);
        return buf; //回复的函数

    }


    ioparse(buf) {
        if (buf.length < 20) return;
        let itl = buf.readUInt16LE(0);
        let conid = buf.readUInt32LE(6);
        let seqn = buf.readUInt32LE(10);
        this.seq = seqn;
        let dataitem = buf.readUInt16LE(14);
        let dleng = buf.readUInt16LE(16);
        dleng = (dleng - 2) / 2;
        let start = 20;  //start 
        if (this.readway == "readUInt16LE") {
            for (let i = 0; i < this.i_size / 2; i++) {//fanuc robot readUInt16LE
                this.rgdb[`${this.host}||UInt[${i}]`] = buf.readUInt16LE(start + i * 2);
            }
        }
        else if (this.readway == "readUInt16BE") {
            for (let i = 0; i < this.i_size / 2; i++) {
                this.rgdb[`${this.host}||UInt[${i}]`] = buf.readUInt16BE(start + i * 2);
            }
        }
        else if (this.readway == "readInt16LE") {
            for (let i = 0; i < this.i_size / 2; i++) {
                this.rgdb[`${this.host}||Int[${i}]`] = buf.readInt16LE(start + i * 2);
            }
        }
        else if (this.readway == "readInt16BE") {
            for (let i = 0; i < this.i_size / 2; i++) {
                this.rgdb[`${this.host}||Int[${i}]`] = buf.readInt16BE(start + i * 2);
            }
        }
        else if (this.readway == "readInt8") {
            for (let i = 0; i < this.i_size; i++) {
                this.rgdb[`${this.host}||Int8[${i}]`] = buf.readInt8(start + i);
            }
        }
        else if (this.readway == "readUInt8") {
            for (let i = 0; i < this.i_size; i++) {
                this.rgdb[`${this.host}||UInt8[${i}]`] = buf.readUInt8(start + i);
            }
        }
        return this.ioresponse();
    }
}


module.exports = { EIP_SCANNER };