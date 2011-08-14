using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using SilinoronParser.Util;

namespace SilinoronParser.Loading.Loaders
{
    [Loader("pkt")]
    public sealed class PktLoader : Loader
    {
        enum Pkt
        {
            V2_1 = 0x0201,
            V2_2 = 0x0202,
            V3 = 0x0300,
            V3_1 = 0x0301,
        }

        public uint Build { get; private set; }

        public PktLoader(string file)
            : base(file)
        {
        }

        public override IEnumerable<Packet> ParseFile()
        {
            using (var gr = new BinaryReader(new FileStream(FileToParse, FileMode.Open, FileAccess.Read), Encoding.ASCII))
            {
                gr.ReadBytes(3);                        // PKT
                var version = (Pkt)gr.ReadUInt16();     // sniff version (0x0201, 0x0202)
                int optionalHeaderLength;
                DateTime startTime = DateTime.Now;
                uint startTickCount = 0;

                switch (version)
                {
                    case Pkt.V2_1:
                        Build = gr.ReadUInt16();        // build
                        gr.ReadBytes(40);               // session key
                        break;
                    case Pkt.V2_2:
                        gr.ReadByte();                  // 0x06
                        Build = gr.ReadUInt16();        // build
                        gr.ReadBytes(4);                // client locale
                        gr.ReadBytes(20);               // packet key
                        gr.ReadBytes(64);               // realm name
                        break;
                    case Pkt.V3:
                        gr.ReadByte();                  // snifferId
                        Build = gr.ReadUInt32();        // client build
                        gr.ReadBytes(4);                // client locale
                        gr.ReadBytes(40);               // session key
                        optionalHeaderLength = gr.ReadInt32();
                        gr.ReadBytes(optionalHeaderLength);
                        break;
                    case Pkt.V3_1:
                        gr.ReadByte();                  // snifferId
                        Build = gr.ReadUInt32();        // client build
                        gr.ReadBytes(4);                // client locale
                        gr.ReadBytes(40);               // session key
                        startTime = Utilities.GetDateTimeFromUnixTime(gr.ReadUInt32());
                        startTickCount = gr.ReadUInt32();
                        optionalHeaderLength = gr.ReadInt32();
                        gr.ReadBytes(optionalHeaderLength);
                        break;
                    default:
                        throw new Exception(String.Format("Unknown sniff version {0:X2}", version));
                }

                var packets = new List<Packet>();

                if (version < Pkt.V3)
                {
                    while (gr.PeekChar() >= 0)
                    {
                        byte direction = (byte)(gr.ReadByte() == 0xff ? 0 : 1);
                        DateTime time = Utilities.GetDateTimeFromUnixTime(gr.ReadUInt32());
                        uint tickcount = gr.ReadUInt32();
                        uint size = gr.ReadUInt32();
                        ushort opcode = (direction == 1) ? (ushort)gr.ReadUInt32() : gr.ReadUInt16();
                        byte[] data = gr.ReadBytes((int)size - ((direction == 1) ? 4 : 2));
                        Packet p = new Packet(data, opcode, time, direction);
                        packets.Add(p);
                    }
                }
                else  // 3.0/3.1
                {
                    while (gr.PeekChar() >= 0)
                    {
                        byte direction = (byte)(gr.ReadUInt32() == 0x47534d53 ? 0 : 1);
                        DateTime time = DateTime.Now;
                        if (version == Pkt.V3)
                            time = Utilities.GetDateTimeFromUnixTime(gr.ReadUInt32());
                        else  // 3.1
                            gr.ReadUInt32(); // sessionID
                        uint tickcount = gr.ReadUInt32();
                        if(version != Pkt.V3) // 3.1: has to be computed
                            time = startTime.AddMilliseconds(tickcount - startTickCount);
                        int optionalSize = gr.ReadInt32();
                        int dataSize = gr.ReadInt32();
                        gr.ReadBytes(optionalSize);
                        ushort opcode = (ushort)gr.ReadUInt32();
                        byte[] data = gr.ReadBytes(dataSize - 4);
                        Packet p = new Packet(data, opcode, time, direction);
                        packets.Add(p);
                    }
                }

                return packets;
            }
        }

    }
}
