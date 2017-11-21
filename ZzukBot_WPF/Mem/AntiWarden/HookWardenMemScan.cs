using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using ZzukBot.ExtensionMethods;
using Ptr = ZzukBot.Constants.Offsets;

namespace ZzukBot.Mem.AntiWarden
{
    internal static class HookWardenMemScan
    {
        /// <summary>
        ///     Delegate to our c# function we will jmp to
        /// </summary>
        private static WardenMemCpyDelegate _wardenMemCpyDelegate;

        /// <summary>
        ///     Delegate to our c# function we will jmp to
        /// </summary>
        private static WardenPageScanDelegate _wardenPageScanDelegate;

        /// <summary>
        ///     First 5 bytes of Wardens Memscan function
        /// </summary>
        private static readonly byte[] MemScanOriginalBytes = {0x56, 0x57, 0xFC, 0x8B, 0x54};

        private static readonly byte[] PageScanOriginalBytes = {0x8B, 0x45, 0x08, 0x8A, 0x04};

        /// <summary>
        ///     Is Wardens Memscan modified?
        /// </summary>
        private static IntPtr WardensMemScanFuncPtr = IntPtr.Zero;

        private static IntPtr WardensPageScanFuncPtr = IntPtr.Zero;

        private static IntPtr WardenMemCpyDetourPtr = IntPtr.Zero;
        private static IntPtr WardenPageScanDetourPtr = IntPtr.Zero;

        private static IntPtr AddrToWardenMemCpy = IntPtr.Zero;
        private static IntPtr AddrToWardenPageScan = IntPtr.Zero;

        /// <summary>
        ///     Delegate to our C# function
        /// </summary>
        private static readonly ModifyWardenDetour _modifyWarden;

        /// <summary>
        ///     A private list to keep track of all hacks registered
        /// </summary>
        private static readonly List<Hack> Hacks = new List<Hack>();

        static HookWardenMemScan()
        {
            Console.WriteLine("HookWardenMemScan created");
            _modifyWarden = DisableWarden;
            // get PTR for our c# function
            var addrToDetour = Marshal.GetFunctionPointerForDelegate(_modifyWarden);
            string[] asmCode =
            {
                "MOV [0xCE8978], EAX",
                "pushfd",
                "pushad",
                "push EAX",
                "call " + (uint)addrToDetour,
                "popad",
                "popfd",
                "jmp 0x006CA233"
            };
            var wardenDetour = Memory.InjectAsm(asmCode, "WardenLoadDetour");
            Memory.InjectAsm(0x006CA22E, "jmp " + wardenDetour, "WardenLoadDetourJmp");
        }

        /// <summary>
        ///     Init the hack
        /// </summary>
        [Obfuscation(Feature = "virtualization", Exclude = false)]
        private static void DisableWarden(IntPtr parWardenPtr1)
        {
            //var second = Memory.Reader.Read<IntPtr>(parWardenPtr1);
            var wardenModuleStart = parWardenPtr1.ReadAs<IntPtr>();
            var memScanPtr = IntPtr.Add(wardenModuleStart, (int) Ptr.Warden.WardenMemScanStart);
            var pageScanPtr = IntPtr.Add(wardenModuleStart, (int) Ptr.Warden.WardenPageScan);

            Console.WriteLine(pageScanPtr.ToString("X"));

            if (pageScanPtr != WardensPageScanFuncPtr)
            {
                var CurrentBytes = Memory.Reader.ReadBytes(pageScanPtr, 5);
                //var CurrrentBytes = (tmpPtr).ReadAs<Byte>(); //How do I read 5 bytes?
                var isEqual = CurrentBytes.SequenceEqual(PageScanOriginalBytes);
                if (!isEqual) return;

                if (AddrToWardenPageScan == IntPtr.Zero)
                {
                    _wardenPageScanDelegate = WardenPageScanHook;
                    AddrToWardenPageScan = Marshal.GetFunctionPointerForDelegate(_wardenPageScanDelegate);
                    if (WardenPageScanDetourPtr == IntPtr.Zero)
                    {
                        // IntPtr readBase, int readOffset, IntPtr writeTo
                        string[] asmCode =
                        {
                            "mov eax, [ebp+8]",
                            "pushfd",
                            "pushad",
                            "mov ecx, esi",
                            "add ecx, edi",
                            "add ecx, 0x1C",
                            "push ecx",
                            "push edi",
                            "push eax",
                            "call " + (uint)AddrToWardenPageScan,
                            "popad",
                            "popfd",
                            "inc edi",
                            "jmp " + ((uint)wardenModuleStart + 0x2B2C)
                        };
                        WardenPageScanDetourPtr = Memory.InjectAsm(asmCode, "WardenPageScanDetour");
                    }
                }

                Memory.InjectAsm((uint) pageScanPtr,
                    "jmp 0x" + WardenPageScanDetourPtr.ToString("X"),
                    "WardenPageScanJmp");
                WardensPageScanFuncPtr = pageScanPtr;
            }

            if (memScanPtr != WardensMemScanFuncPtr)
            {
                var CurrentBytes = Memory.Reader.ReadBytes(memScanPtr, 5);
                //var CurrrentBytes = (tmpPtr).ReadAs<Byte>(); //How do I read 5 bytes?
                var isEqual = CurrentBytes.SequenceEqual(MemScanOriginalBytes);
                if (!isEqual) return;

                if (AddrToWardenMemCpy == IntPtr.Zero)
                {
                    _wardenMemCpyDelegate = WardenMemCpyHook;
                    AddrToWardenMemCpy = Marshal.GetFunctionPointerForDelegate(_wardenMemCpyDelegate);

                    if (WardenMemCpyDetourPtr == IntPtr.Zero)
                    {
                        string[] asmCodeOnline =
                        {
                            "PUSH ESI",
                            "PUSH EDI",
                            "CLD",
                            "MOV EDX, [ESP+20]",
                            "MOV ESI, [ESP+16]",
                            "MOV EAX, [ESP+12]",
                            "MOV ECX, EDX",
                            "MOV EDI, EAX",
                            "pushfd",
                            "pushad",
                            "PUSH EDI",
                            "PUSH ECX",
                            "PUSH ESI",
                            "call " + "0x" + ((uint) AddrToWardenMemCpy).ToString("X"),
                            "popad",
                            "popfd",
                            "POP EDI",
                            "POP ESI",
                            "jmp " + "0x" + ((uint) (memScanPtr + 0x24)).ToString("X")
                        };
                        WardenMemCpyDetourPtr = Memory.InjectAsm(asmCodeOnline, "WardenMemCpyDetour");
                    }
                }

                Memory.InjectAsm((uint) memScanPtr, "jmp 0x" + WardenMemCpyDetourPtr.ToString("X"), "WardenMemCpyJmp");
                WardensMemScanFuncPtr = memScanPtr;
            }
        }

        /// <summary>
        ///     add a hack to the list from the outside
        ///     hack contains: original bytes, bytes we inject, the address we inject to
        /// </summary>
        internal static void AddHack(Hack parHack)
        {
            if (Hacks.All(i => i.Address != parHack.Address))
            {
                RemoveHack(parHack.Name);
                Hacks.Add(parHack);
            }
        }

        internal static void RemoveHack(string parName)
        {
            var hack = Hacks.Where(i => i.Name == parName).ToList();
            foreach (var x in hack)
                x.Remove();
            Hacks.RemoveAll(i => i.Name == parName);
        }

        internal static void RemoveHack(IntPtr parAddress)
        {
            var hack = Hacks.Where(i => i.Address == parAddress).ToList();
            foreach (var x in hack)
                x.Remove();
            Hacks.RemoveAll(i => i.Address == parAddress);
        }

        internal static Hack GetHack(string parName)
        {
            return Hacks.FirstOrDefault(i => i.Name == parName);
        }

        internal static Hack GetHack(IntPtr parAddress)
        {
            return Hacks.FirstOrDefault(i => i.Address == parAddress);
        }


        private static void WardenPageScanHook(IntPtr readBase, int readOffset, IntPtr writeTo)
        {
            var readByteFrom = readBase + readOffset;

            var activeHacks = Hacks.Where(x => x.IsActivated && x.IsWithinScan(readByteFrom, 1)).ToList();
            activeHacks.ForEach(x =>
            {
                x.Remove();
                Console.WriteLine($@"[PageScan] Disabling {x.Name} at {x.Address.ToString("X")}");
            });
            var myByte = Memory.Reader.Read<byte>(readByteFrom);
            Memory.Reader.Write(writeTo, myByte);

            activeHacks.ForEach(x => x.Apply());
        }

        /// <summary>
        ///     Will be called from our ASM stub
        ///     will check if the scanned addr range contains any registered hack
        ///     if yes: restore original byte for the hack
        ///     do the scan
        ///     restore back to the "hacked" state
        /// </summary>
        private static void WardenMemCpyHook(IntPtr addr, int size, IntPtr bufferStart)
        {
            if (size != 0)
            {
                // LINQ to get all affected hacks
                var match = Hacks
                    .Where(i => i.Address.ToInt32() <= IntPtr.Add(addr, size).ToInt32()
                                && i.Address.ToInt32() >= addr.ToInt32())
                    .ToList();

                var ActiveHacks = new List<Hack>();
                foreach (var x in match)
                {
                    if (!x.IsActivated) continue;
                    ActiveHacks.Add(x);
                    x.Remove();
                }
                // Do the memscan
                Memory.Reader.WriteBytes(bufferStart, Memory.Reader.ReadBytes(addr, size));
                // reapply
                ActiveHacks.ForEach(i => i.Apply());
            }
        }


        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void ModifyWardenDetour(IntPtr parWardenPtr);

        /// <summary>
        ///     Delegate for our c# function
        /// </summary>
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void WardenMemCpyDelegate(IntPtr addr, int size, IntPtr bufferStart);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate void WardenPageScanDelegate(IntPtr readBase, int readOffset, IntPtr writeTo);
    }
}