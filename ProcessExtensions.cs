/*
 MIT License

Copyright (c) 2019 differentrain

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. 
 */

/*
 Requirements:
     Windows Vista or later;
     Intel CPU;
     C# 7.3
     .NET Frameworks 4.5;
  
  Build Options:
     Choose 'Any CPU' platform;
     Enable 'Allow unsafe code';
     Disable 'Prefer 32 bit'
     
   Some members may need administrative rights.  
*/
using Microsoft.Win32.SafeHandles;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Linq;
using System.Linq.Expressions;

namespace System.Diagnostics.ProcessExtensions
{
    /// <summary>
    /// Represents the implementation for the <see cref="Process"/> class enhancement. 
    /// </summary>
    /// <remarks>
    /// Members in this class may need administrative rights. 
    /// </remarks>
    public class ProcessPlugin : IDisposable
    {

        #region properties & fields

        internal readonly IntPtr _maxMemory;

        private readonly bool _leaveOpen;

        /// <summary>
        /// Gets a reference to the underlying <see cref="Process"/> instance.
        /// </summary>
        public Process BaseProcess { get; private set; }

        /// <summary>
        /// Gets the allocated memories. see <see cref="AllocatedMemories"/> class.
        /// </summary>
        public AllocatedMemoryCollection AllocatedMemories { get; private set; }

        /// <summary>
        ///  Gets a reference to an <see cref="AdvancedFeature"/> instance which provides advanced features.
        /// </summary>
        public AdvancedFeature Advanced { get; private set; }

        /// <summary>
        /// Gets the main window class name of the process.
        /// </summary>
        public string MainWindowClassName => InnerUtilities.GetWindowClassByHandle(BaseProcess);

        /// <summary>
        /// Gets a value indicates that whether the process opened with <see cref="Process"/> is an 64 bit process.
        /// </summary>
        public bool Is64BitProcess => Environment.Is64BitProcess ?
                                          InnerUtilities.NativeMethods.IsWow64Process(new HandleRef(BaseProcess, BaseProcess.Handle), out var isWow) && !isWow ?
                                               true :
                                               false :
                                          false;


        #endregion

        #region constructors


        /// <summary>
        /// Static constructor, meant to check environment.
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1065:DoNotRaiseExceptionsInUnexpectedLocations")]
        static ProcessPlugin()
        {
            if (Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess)
            {
                throw new PlatformNotSupportedException("Request 'Any CPU' platform and make sure that 'Prefer 32 bit' setting is disabled.");
            }
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="ProcessPlugin"/> class, by using the specified <see cref="process"/> instance.
        /// </summary>
        /// <param name="process"></param>
        public ProcessPlugin(Process process) : this(process, false) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="ProcessPlugin"/> class, by using the specified <see cref="process"/> instance, and optionally leaves the <see cref="process"/> instance open.
        /// </summary>
        /// <param name="process">The process instance.</param>
        /// <param name="leaveOpen"><c>true</c> to leave the <see cref="Process"/> object open after disposing the <see cref="ProcessInfo"/> object; otherwise, <c>false.</c></param>
        public ProcessPlugin(Process process, bool leaveOpen)
        {
            BaseProcess = process ?? throw new ArgumentNullException("process");
            _leaveOpen = leaveOpen;
            _maxMemory = Is64BitProcess ?
                        InnerUtilities.SystemInfo.MaximumApplicationAddress :
                        new IntPtr((int)(InnerUtilities.SystemInfo.MaximumApplicationAddress.ToInt64() & 0x7FFFFFFF));
            AllocatedMemories = new AllocatedMemoryCollection(this);
            Advanced = new AdvancedFeature(this);
        }
        #endregion

        #region methods

        /// <summary>
        /// Gets the Module by specified module name.
        /// </summary>
        /// <param name="moduleName">The module name, include the file name extension.</param>
        /// <returns></returns>
        public ProcessModuleAlter GetModuleByName(string moduleName) => InnerUtilities.GetModuleByName(BaseProcess, moduleName);

        /// <summary>
        /// Read a value of <typeparamref name="T"/> type from the specified address in process.
        /// </summary>
        /// <typeparam name="T">The unmanged type.</typeparam>
        /// <param name="address">The address.</param>
        /// <returns><typeparamref name="T"/></returns>
        public T ReadData<T>(IntPtr address) where T : unmanaged => InnerUtilities.ReadData<T>(BaseProcess, address);
        /// <summary>
        /// Read a sequence of values of <typeparamref name="T"/> type from the specified address in process.
        /// </summary>
        /// <typeparam name="T">The unmanged type.</typeparam>
        /// <param name="address">The address.</param>
        /// <param name="count">The number of elements in the <typeparamref name="T"/> sequence.</param>
        /// <returns></returns>
        public T[] ReadData<T>(IntPtr address, int count) where T : unmanaged => InnerUtilities.ReadData<T>(BaseProcess, address, count);
        /// <summary>
        ///  Read a sequence of <typeparamref name="T"/> type from the specified address in process.
        /// </summary>
        /// <typeparam name="T">The unmanged type.</typeparam>
        /// <param name="address">The address.</param>
        /// <param name="data">The <typeparamref name="T"/>sequence to store the read values.</param>
        /// <param name="startIndex">The start index of <paramref name="data"/>.</param>
        /// <param name="count">The count of <typeparamref name="T"/> type date to be read.</param>
        public void ReadData<T>(IntPtr address, T[] data, int startIndex, int count) where T : unmanaged => InnerUtilities.ReadData<T>(BaseProcess, address, data, startIndex, count);

        /// <summary>
        /// Writes  <typeparamref name="T"/> type data to the specified address in process.
        /// </summary>
        /// <typeparam name="T">The unmanged type.</typeparam>
        /// <param name="address">The address.</param>
        /// <param name="data">The date to be written.</param>
        public void WriteData<T>(IntPtr address, params T[] data) where T : unmanaged => InnerUtilities.WriteData<T>(BaseProcess, address, data);

        /// <summary>
        ///  Write a sequence of <typeparamref name="T"/> type from the specified address in process.
        /// </summary>
        /// <typeparam name="T">The unmanged type.</typeparam>
        /// <param name="address">The address.</param>
        /// <param name="data">The <typeparamref name="T"/>sequence to be wirtten.</param>
        /// <param name="startIndex">The start index of <paramref name="data"/>.</param>
        /// <param name="count">The count of <typeparamref name="T"/> type date to be written in <paramref name="data"/>.</param>
        public void WriteData<T>(IntPtr address, T[] data, int startIndex, int count) where T : unmanaged => InnerUtilities.WriteData<T>(BaseProcess, address, data, startIndex, count);

        /// <summary>
        /// Searches the specified bytes in process memory. <see cref="IntPtr.Zero"/> means failed.
        /// </summary>
        /// <param name="pattern">The bytes to be searched.</param>
        /// <returns></returns>
        public IntPtr ScanBytes(byte[] pattern) => ScanBytes(pattern, IntPtr.Zero, _maxMemory, MemoryProtectionFilter.ExecuteRead);
        /// <summary>
        /// Searches the specified bytes in process memory, with the specified filter. <see cref="IntPtr.Zero"/> means failed.
        /// </summary>
        /// <param name="pattern">The bytes to be searched.</param>
        /// <param name="filter">The filter.</param>
        /// <returns></returns>
        public IntPtr ScanBytes(byte[] pattern, MemoryProtectionFilter filter) => ScanBytes(pattern, IntPtr.Zero, _maxMemory, filter);
        /// <summary>
        /// Searches the specified bytes in process memory, with the specified start address. <see cref="IntPtr.Zero"/> means failed.
        /// </summary>
        /// <param name="pattern">The bytes to be searched.</param>
        /// <param name="addressStart">The start address.</param>
        /// <returns></returns>
        public IntPtr ScanBytes(byte[] pattern, IntPtr addressStart) => ScanBytes(pattern, addressStart, _maxMemory, MemoryProtectionFilter.ExecuteRead);
        /// <summary>
        /// Searches the specified bytes in process memory, with the specified search scope. <see cref="IntPtr.Zero"/> means failed.
        /// </summary>
        /// <param name="pattern">The bytes to be searched.</param>
        /// <param name="addressStart">The start address.</param>
        /// <param name="addressEnd">The end address.</param>
        /// <returns></returns>
        public IntPtr ScanBytes(byte[] pattern, IntPtr addressStart, IntPtr addressEnd) => ScanBytes(pattern, addressStart, addressEnd, MemoryProtectionFilter.ExecuteRead);
        /// <summary>
        /// Searches the specified bytes in process memory, with the specified filter and search scope. <see cref="IntPtr.Zero"/> means failed.
        /// </summary>
        /// <param name="pattern">The bytes to be searched.</param>
        /// <param name="addressStart">The start address.</param>
        /// <param name="addressEnd">The end address.</param>
        /// <param name="filter">The filter.</param>
        /// <returns></returns>
        public IntPtr ScanBytes(byte[] pattern, IntPtr addressStart, IntPtr addressEnd, MemoryProtectionFilter filter) => InnerUtilities.ScanByteArray(BaseProcess, pattern, BytesFinder.FindIndex, addressStart, addressEnd, filter);

        /// <summary>
        /// Wildcard version. pattern supports wildcard(?) .
        /// </summary>
        /// <param name="pattern"></param>
        /// <returns></returns>
        public IntPtr ScanBytes(BytesFinder pattern) => ScanBytes(pattern, IntPtr.Zero, _maxMemory, MemoryProtectionFilter.ExecuteRead);
        /// <summary>
        /// Wildcard version. pattern supports wildcard(?) .
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <returns></returns>
        public IntPtr ScanBytes(BytesFinder pattern, IntPtr addressStart) => ScanBytes(pattern, addressStart, _maxMemory, MemoryProtectionFilter.ExecuteRead);
        /// <summary>
        /// Wildcard version. pattern supports wildcard(?) .
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <returns></returns>
        public IntPtr ScanBytes(BytesFinder pattern, IntPtr addressStart, IntPtr addressEnd) => ScanBytes(pattern, addressStart, addressEnd, MemoryProtectionFilter.ExecuteRead);

        /// <summary>
        /// Wildcard version. pattern supports wildcard(?) .
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <param name="filter"></param>
        /// <returns></returns>
        public IntPtr ScanBytes(BytesFinder pattern, IntPtr addressStart, IntPtr addressEnd, MemoryProtectionFilter filter) => InnerUtilities.ScanByteArray(
            BaseProcess, null,
            new Func<byte[], byte[], int>((x, y) => pattern.FindIndexIn(x)),
            addressStart, addressEnd, filter);



        /// <summary>
        /// Async version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(byte[] pattern, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, IntPtr.Zero, _maxMemory, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="filter"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(byte[] pattern, MemoryProtectionFilter filter, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, IntPtr.Zero, _maxMemory, filter, callBack);
        /// <summary>
        /// Async version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(byte[] pattern, IntPtr addressStart, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, addressStart, _maxMemory, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(byte[] pattern, IntPtr addressStart, IntPtr addressEnd, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, addressStart, addressEnd, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <param name="filter"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(byte[] pattern, IntPtr addressStart, IntPtr addressEnd, MemoryProtectionFilter filter, Action<IntPtr> callBack = null) => await Task.Run(() =>
        {
            var result = ScanBytes(pattern, addressStart, addressEnd, filter);
            callBack?.Invoke(result);
            return result;
        });


        /// <summary>
        /// Async wildcard version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(BytesFinder pattern, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, IntPtr.Zero, _maxMemory, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async wildcard version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="filter"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(BytesFinder pattern, MemoryProtectionFilter filter, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, IntPtr.Zero, _maxMemory, filter, callBack);
        /// <summary>
        /// Async wildcard version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(BytesFinder pattern, IntPtr addressStart, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, addressStart, _maxMemory, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async wildcard version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(BytesFinder pattern, IntPtr addressStart, IntPtr addressEnd, Action<IntPtr> callBack = null) => await ScanBytesAsync(pattern, addressStart, addressEnd, MemoryProtectionFilter.ExecuteRead, callBack);
        /// <summary>
        /// Async wildcard version. The result also can be get form <paramref name="callBack"/>.
        /// </summary>
        /// <param name="pattern"></param>
        /// <param name="addressStart"></param>
        /// <param name="addressEnd"></param>
        /// <param name="filter"></param>
        /// <param name="callBack"></param>
        /// <returns></returns>
        public async Task<IntPtr> ScanBytesAsync(BytesFinder pattern, IntPtr addressStart, IntPtr addressEnd, MemoryProtectionFilter filter, Action<IntPtr> callBack = null) => await Task.Run(() =>
        {
            var result = ScanBytes(pattern, addressStart, addressEnd, filter);
            callBack?.Invoke(result);
            return result;
        });



        /// <summary>
        /// Calls the remote function in target process.
        /// </summary>
        /// <param name="address">The address of the function.</param>
        /// <returns></returns>
        public RemoteCallState CallRemoteFunction(IntPtr address) => CallRemoteFunction(address, InnerUtilities.INFINITE_INT);
        /// <summary>
        /// Calls the remote function in target process.
        /// </summary>
        /// <param name="address">The address of the function.</param>
        /// <param name="timeOut">Timeout, in ms.</param>
        /// <returns></returns>
        public RemoteCallState CallRemoteFunction(IntPtr address, int timeOut) => InnerUtilities.CallRemoteFunc(BaseProcess, address, timeOut);
        /// <summary>
        /// Calls the remote function in target process.
        /// </summary>
        /// <param name="address">The address of the function.</param>
        /// <param name="callBack">call back.</param>
        /// <returns></returns>
        public async Task<RemoteCallState> CallRemoteFunctionAsync(IntPtr address, Action<RemoteCallState> callBack = null) => await CallRemoteFunctionAsync(address, InnerUtilities.INFINITE_INT, callBack);
        /// <summary>
        /// Calls the remote function in target process.
        /// </summary>
        /// <param name="address">The address of the function.</param>
        /// <param name="timeOut">Timeout, in ms.</param>
        /// <param name="callBack">call back.</param>
        /// <returns></returns>
        public async Task<RemoteCallState> CallRemoteFunctionAsync(IntPtr address, int timeOut, Action<RemoteCallState> callBack = null) => await Task.Run(() =>
        {
            var result = CallRemoteFunction(address, timeOut);
            callBack?.Invoke(result);
            return result;
        });

        /// <summary>
        /// Get a new instance of <see cref="Process"/> which is open the process with the specified main window name.
        /// <para>returns null if not succeed.</para>
        /// </summary>
        /// <param name="windowName">Main window name.</param>
        /// <returns></returns>
        public static Process GetProcessByWindow(string windowName) => GetProcessByWindow(windowName, null);
        /// <summary>
        ///  Get a new instance of <see cref="Process"/> which is open the process with the specified main window name and class name.
        ///  <para>returns null if not succeed.</para>
        /// </summary>
        /// <param name="windowName">Main window name.</param>
        /// <param name="windowClass">Main window class name.</param>
        /// <returns></returns>
        public static Process GetProcessByWindow(string windowName, string windowClass) => InnerUtilities.GetProcessByWindow(windowName, windowClass);

        #endregion

        #region IDisposable Support
        private bool _disposed = false;
        /// <summary>
        /// Dispose mode.
        /// </summary>
        /// <param name="disposing"></param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (BaseProcess != null)
                    {
                        AllocatedMemories.Dispose();
                        Advanced.Dispose();
                        if (!_leaveOpen)
                        {
                            BaseProcess.Dispose();
                        }
                    }
                }
                Advanced = null;
                AllocatedMemories = null;
                BaseProcess = null;
                _disposed = true;
            }
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
        }
        #endregion

        /// <summary>
        /// A class provieds some advanced features to get the process infomation.
        /// </summary>
        public sealed class AdvancedFeature
        {
            private static readonly byte[] _Asmcode64 = new byte[]
            {
                0x48,0x83,0xEC,0x20,0x65,0x4C,0x8B,0x04,0x25,0x60,0x00,0x00,0x00,0x4D,0x8B,0x40,0x18,0x4D,0x8B,0x40,0x20,0x4D,0x8B,0x00,0x49,0xBB,0x4B,0x00,0x45,0x00,0x52,0x00,0x4E,
                0x00,0x49,0xB9,0x45,0x00,0x4C,0x00,0x33,0x00,0x32,0x00,0x48,0xB9,0x2E,0x00,0x44,0x00,0x4C,0x00,0x4C,0x00,0x4D,0x8B,0x00,0x49,0x8B,0x40,0x50,0x4C,0x39,0x18,0x75,0xF4,
                0x4C,0x39,0x48,0x08,0x75,0xEE,0x48,0x39,0x48,0x10,0x75,0xE8,0x81,0x78,0x16,0x4C,0x00,0x00,0x00,0x75,0xDF,0x4D,0x8B,0x40,0x20,0x4D,0x31,0xC9,0x45,0x8B,0x48,0x3C,0x4D,
                0x01,0xC1,0x45,0x8B,0x89,0x88,0x00,0x00,0x00,0x4D,0x01,0xC1,0x48,0x89,0x74,0x24,0x18,0x48,0x31,0xF6,0x41,0x8B,0x71,0x20,0x4C,0x01,0xC6,0x45,0x8B,0x51,0x24,0x4D,0x01,
                0xC2,0x48,0x31,0xC9,0x48,0x31,0xC0,0x49,0xBB,0x47,0x65,0x74,0x50,0x72,0x6F,0x63,0x41,0xFF,0xC1,0xAD,0x4C,0x01,0xC0,0x4C,0x39,0x18,0x75,0xF5,0x81,0x78,0x08,0x64,0x64,
                0x72,0x65,0x75,0xEC,0x81,0x78,0x0B,0x65,0x73,0x73,0x00,0x75,0xE3,0x48,0x8B,0x74,0x24,0x18,0x66,0x41,0x8B,0x0C,0x4A,0xFF,0xC9,0x45,0x8B,0x49,0x1C,0x4D,0x01,0xC1,0x45,
                0x8B,0x0C,0x89,0x4D,0x01,0xC1,0x4C,0x89,0x0D,0xB9,0x05,0x00,0x00,0x49,0x8B,0xC8,0x48,0x8D,0x15,0xC6,0x02,0x00,0x00,0x41,0xFF,0xD1,0x4C,0x8B,0xC8,0x4C,0x89,0x0D,0xAA,
                0x05,0x00,0x00,0xC7,0x05,0x78,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D,0xB9,0x02,0x00,0x00,0xFF,0x15,0x93,0x05,0x00,0x00,0x48,0x85,0xC0,0x75,0x1A,0x90,0x90,
                0x90,0x90,0x48,0x8D,0x0D,0xB5,0x02,0x00,0x00,0xFF,0x15,0x7D,0x05,0x00,0x00,0x48,0x85,0xC0,0x0F,0x84,0xBB,0x00,0x00,0x00,0x48,0x8B,0xC8,0x48,0x89,0x0D,0x3A,0x05,0x00,
                0x00,0x48,0x8D,0x15,0xBB,0x02,0x00,0x00,0xFF,0x15,0x55,0x05,0x00,0x00,0x48,0x85,0xC0,0x0F,0x84,0x9B,0x00,0x00,0x00,0xC7,0x05,0x22,0x05,0x00,0x00,0x01,0x00,0x00,0x00,
                0x48,0x89,0x35,0x4B,0x05,0x00,0x00,0x48,0x89,0x3D,0x24,0x05,0x00,0x00,0x48,0xBE,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8D,0x3D,0x83,0x02,0x00,0x00,0x48,0x89,
                0x47,0x28,0x48,0x8B,0x0D,0xF0,0x04,0x00,0x00,0x48,0x8D,0x14,0x3E,0xFF,0x15,0x0E,0x05,0x00,0x00,0x48,0x83,0xC6,0x28,0x48,0x89,0x04,0x3E,0x48,0x83,0xC6,0x08,0x48,0x81,
                0xFE,0x70,0x02,0x00,0x00,0x75,0xDA,0x48,0x8B,0x35,0x02,0x05,0x00,0x00,0x48,0x8B,0x3D,0xDB,0x04,0x00,0x00,0xFF,0x15,0x6D,0x02,0x00,0x00,0x4C,0x8B,0xC8,0x4C,0x89,0x0D,
                0xAB,0x04,0x00,0x00,0x48,0x8B,0xC8,0xFF,0x15,0x8A,0x02,0x00,0x00,0xC7,0x05,0xA0,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x48,0x8D,0x0D,0x45,0x00,0x00,0x00,0x48,0xBA,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xFF,0x15,0x99,0x02,0x00,0x00,0x48,0x83,0xC4,0x20,0xC3,0x48,0x83,0xEC,0x28,0x48,0x8D,0x0D,0xB9,0x04,0x00,0x00,0xFF,0x15,0xA3,0x04,
                0x00,0x00,0x48,0x8B,0xC8,0x48,0x8D,0x15,0xE9,0x04,0x00,0x00,0xFF,0x15,0x8B,0x04,0x00,0x00,0x4C,0x8B,0xC8,0x4C,0x89,0x0D,0x91,0x04,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,
                0xFF,0x15,0x8E,0x02,0x00,0x00,0x8B,0x0D,0x48,0x04,0x00,0x00,0x81,0xF9,0x80,0x03,0x00,0x00,0x74,0x30,0x90,0x90,0x90,0x90,0x4C,0x8D,0x05,0xB5,0x05,0x00,0x00,0x4A,0x89,
                0x04,0x01,0x48,0x8B,0xC8,0xFF,0x15,0x98,0x02,0x00,0x00,0x8B,0x0D,0x22,0x04,0x00,0x00,0x4C,0x8D,0x05,0x9B,0x08,0x00,0x00,0x4A,0x89,0x04,0x01,0x83,0x05,0x10,0x04,0x00,
                0x00,0x08,0xC3,0x48,0x83,0xEC,0x28,0x48,0x8D,0x0D,0x1C,0x04,0x00,0x00,0xC7,0x01,0x00,0x00,0x00,0x00,0x48,0x8B,0x0D,0xEF,0x03,0x00,0x00,0xFF,0x15,0xD1,0x01,0x00,0x00,
                0x48,0x8B,0x0D,0xFA,0x03,0x00,0x00,0x48,0x8D,0x15,0xA3,0x04,0x00,0x00,0x4C,0x8D,0x05,0xDC,0x04,0x00,0x00,0xFF,0x15,0x76,0x02,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,0x48,
                0x83,0xEC,0x28,0xE8,0xB9,0xFF,0xFF,0xFF,0x48,0x85,0xC0,0x74,0x30,0x90,0x90,0x90,0x90,0x48,0x8B,0x0D,0xB0,0x03,0x00,0x00,0x48,0x8B,0xD0,0xFF,0x15,0x7F,0x02,0x00,0x00,
                0x48,0x85,0xC0,0x74,0x17,0x90,0x90,0x90,0x90,0x48,0x8B,0xC8,0xFF,0x15,0x9D,0x02,0x00,0x00,0x4C,0x8B,0xC8,0x4C,0x89,0x0D,0xAB,0x03,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,
                0x48,0x83,0xEC,0x28,0xE8,0x76,0xFF,0xFF,0xFF,0x48,0x85,0xC0,0x74,0x3A,0x90,0x90,0x90,0x90,0x48,0x8B,0xC8,0x48,0x8D,0x15,0xB2,0x04,0x00,0x00,0x49,0xB8,0xFF,0xFF,0xFF,
                0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x15,0x92,0x02,0x00,0x00,0x48,0x85,0xC0,0x74,0x17,0x90,0x90,0x90,0x90,0x48,0x8B,0xC8,0xFF,0x15,0xB0,0x02,0x00,0x00,0x4C,0x8B,0xC8,0x4C,
                0x89,0x0D,0x5E,0x03,0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,0x48,0x83,0xEC,0x28,0xE8,0x29,0xFF,0xFF,0xFF,0x48,0x85,0xC0,0x74,0x6D,0x90,0x90,0x90,0x90,0x48,0x8B,0xC8,0x48,
                0x8D,0x15,0x65,0x04,0x00,0x00,0x49,0xB8,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x15,0xA5,0x02,0x00,0x00,0x48,0x85,0xC0,0x74,0x4A,0x90,0x90,0x90,0x90,0x48,0x8B,
                0xC8,0x83,0x3D,0x22,0x03,0x00,0x00,0x00,0x75,0x18,0x90,0x90,0x90,0x90,0xFF,0x15,0xB6,0x02,0x00,0x00,0xEB,0x12,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
                0x90,0xFF,0x15,0xD2,0x02,0x00,0x00,0x48,0x85,0xC0,0x74,0x17,0x90,0x90,0x90,0x90,0x48,0x8B,0xC8,0xFF,0x15,0x30,0x02,0x00,0x00,0x4C,0x8B,0xC8,0x4C,0x89,0x0D,0xDE,0x02,
                0x00,0x00,0x48,0x83,0xC4,0x28,0xC3,0x47,0x65,0x74,0x4D,0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65,0x57,0x00,0x6D,0x00,0x6F,0x00,0x6E,0x00,0x6F,0x00,0x2E,
                0x00,0x64,0x00,0x6C,0x00,0x6C,0x00,0x00,0x00,0x6D,0x00,0x6F,0x00,0x6E,0x00,0x6F,0x00,0x2D,0x00,0x32,0x00,0x2E,0x00,0x30,0x00,0x2D,0x00,0x62,0x00,0x64,0x00,0x77,0x00,
                0x67,0x00,0x63,0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x67,0x65,0x74,0x5F,0x72,0x6F,0x6F,0x74,0x5F,0x64,0x6F,0x6D,0x61,0x69,
                0x6E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,
                0x5F,0x74,0x68,0x72,0x65,0x61,0x64,0x5F,0x61,0x74,0x74,0x61,0x63,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x5F,0x66,0x6F,0x72,0x65,0x61,0x63,0x68,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x61,0x73,
                0x73,0x65,0x6D,0x62,0x6C,0x79,0x5F,0x67,0x65,0x74,0x5F,0x69,0x6D,0x61,0x67,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x69,0x6D,0x61,0x67,0x65,0x5F,0x67,0x65,0x74,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,
                0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x76,0x74,0x61,0x62,0x6C,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x76,0x74,0x61,0x62,0x6C,0x65,0x5F,0x67,
                0x65,0x74,0x5F,0x73,0x74,0x61,0x74,0x69,0x63,0x5F,0x66,0x69,0x65,0x6C,0x64,0x5F,0x64,0x61,0x74,0x61,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x67,0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6F,0x6D,0x70,0x69,0x6C,0x65,0x5F,0x6D,0x65,0x74,
                0x68,0x6F,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,
                0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x67,0x65,0x74,0x5F,0x70,0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x70,0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x67,0x65,0x74,0x5F,0x67,
                0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,
                0x5F,0x70,0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x67,0x65,0x74,0x5F,0x73,0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x00,0x00
            };

            #region fields
            private ProcessPlugin _plugin;
            private bool _injected = false;
            private IntPtr _allocMem;
            private readonly bool _X64;


            private int _callGetFuncOffset;
            private int _addrModuleNameOffset;
            private int _addrFunctionNameOffset;
            private int _addrNativeResultOffset;
            private int _callGetStaticFieldsOffset;
            private int _callGetMethodOffset;
            private int _callGetPropertyOffset;
            private int _addrImagePointerOffset;
            private int _addrNamespaceStrOffset;
            private int _addrMonoResultOffset;
            private int _addrParaOffset;
            private int _isMonoOffset;
            private int _asmIdxOffset;
            private int _addrImagesOffset;
            private int _addrNamesOffset;
            #endregion

            internal AdvancedFeature(ProcessPlugin plugin)
            {
                _plugin = plugin;
                _X64 = plugin.Is64BitProcess;
            }

            /// <summary>
            /// Gets or set whether these features have been enabled.
            /// </summary>
            public bool Enabled
            {
                get => _injected;
                set
                {
                    if (value == _injected) return;

                    if (value)
                    {
                        _allocMem = InnerUtilities.AllocMemory(_plugin, IntPtr.Zero, 4096);


                        byte[] asmCodes;

                        if (_X64)
                        {
                            _callGetFuncOffset = 0x1E0;
                            _addrModuleNameOffset = 0x6A4;
                            _addrFunctionNameOffset = 0x6E4;
                            _addrNativeResultOffset = 0x69C;
                            _callGetStaticFieldsOffset = 0x293;
                            _callGetMethodOffset = 0x2D6;
                            _callGetPropertyOffset = 0x323;
                            _addrImagePointerOffset = 0x674;
                            _addrNamespaceStrOffset = 0x724;
                            _addrMonoResultOffset = 0x67C;
                            _addrParaOffset = 0x684;
                            _isMonoOffset = 0x66C;
                            _asmIdxOffset = 0x664;
                            _addrImagesOffset = 0x7E4;
                            _addrNamesOffset = 0xAE4;

                            asmCodes = _Asmcode64;
                        }
                        else
                        {

                            #region MyRegion

                            _callGetFuncOffset = 0x163;
                            _addrModuleNameOffset = 0x51F;
                            _addrFunctionNameOffset = 0x59F;
                            _addrNativeResultOffset = 0x507;
                            _callGetStaticFieldsOffset = 0x1FB;
                            _callGetMethodOffset = 0x230;
                            _callGetPropertyOffset = 0x266;
                            _addrImagePointerOffset = 0x513;
                            _addrNamespaceStrOffset = 0x61F;
                            _addrMonoResultOffset = 0x517;
                            _addrParaOffset = 0x51B;
                            _isMonoOffset = 0x4FB;
                            _asmIdxOffset = 0x50F;
                            _addrImagesOffset = 0x6DF;
                            _addrNamesOffset = 0x85F;

                            #endregion

                            #region MyRegion



                            var intAddr = _allocMem.ToInt32();


                            var asmIndexAddress = BitConverter.GetBytes(intAddr + _asmIdxOffset);
                            var isMonoAddress = BitConverter.GetBytes(intAddr + _isMonoOffset);
                            var addrModuleNameAddress = BitConverter.GetBytes(intAddr + _addrModuleNameOffset);
                            var addrFunctionNameAddress = BitConverter.GetBytes(intAddr + _addrFunctionNameOffset);
                            var addrNativeResultAddress = BitConverter.GetBytes(intAddr + _addrNativeResultOffset);
                            var addrImagesAddress = BitConverter.GetBytes(intAddr + _addrImagesOffset);
                            var addrNamesAddress = BitConverter.GetBytes(intAddr + _addrNamesOffset);
                            var addrMonoResultAddress = BitConverter.GetBytes(intAddr + _addrMonoResultOffset);
                            var addrNamespaceStrAddress = BitConverter.GetBytes(intAddr + _addrNamespaceStrOffset);
                            var addrAddrImagePointerAddress = BitConverter.GetBytes(intAddr + _addrImagePointerOffset);
                            var addrParaAddress = BitConverter.GetBytes(intAddr + _addrParaOffset);

                            var addrMemberStr = BitConverter.GetBytes(intAddr + 0x69F);
                            var addrClassStr = BitConverter.GetBytes(intAddr + 0x65F);
                            var addrGetProcAddress = BitConverter.GetBytes(intAddr + 0x4FF);
                            var addrGetModuleHandleW = BitConverter.GetBytes(intAddr + 0x503);
                            var addrGetDomain = BitConverter.GetBytes(intAddr + 0x32F);
                            var addrThreadAttch = BitConverter.GetBytes(intAddr + 0x355);
                            var addrDomainForeach = BitConverter.GetBytes(intAddr + 0x37B);
                            var addrDomain = BitConverter.GetBytes(intAddr + 0x50B);
                            var addrCallback = BitConverter.GetBytes(intAddr + 0x180);
                            var addrGetImage = BitConverter.GetBytes(intAddr + 0x3A1);

                            var addrGetImageName = BitConverter.GetBytes(intAddr + 0x3C7);
                            var addrGetClass = BitConverter.GetBytes(intAddr + 0x3ED);
                            var addrGetVtable = BitConverter.GetBytes(intAddr + 0x413);
                            var addrGetStaticFields = BitConverter.GetBytes(intAddr + 0x439);
                            var addrGetMethod = BitConverter.GetBytes(intAddr + 0x45F);
                            var addrComMethod = BitConverter.GetBytes(intAddr + 0x485);
                            var addrGetProperty = BitConverter.GetBytes(intAddr + 0x4AB);
                            var addrGetter = BitConverter.GetBytes(intAddr + 0x4D1);
                            var addrSetter = BitConverter.GetBytes(intAddr + 0x4F7);

                            var strMonoDll = BitConverter.GetBytes(intAddr + 0x2D5);
                            var strMonoDLLB = BitConverter.GetBytes(intAddr + 0x2E7);
                            var strGetModuleHandleW = BitConverter.GetBytes(intAddr + 0x2C4);
                            var strGetDomain = BitConverter.GetBytes(intAddr + 0x30D);

                            #endregion
                            asmCodes = new byte[] {0x31,0xC9,0x64,0x8B,0x41,0x30,0x8B,0x40,0x0C,0x8B,0x70,0x14,0xAD,0x96,0xAD,0x8B,0x58,0x28,0x81,0x3B,0x4B,0x00,0x45,0x00,0x75,
                                              0xF3,0x81,0x7B,0x04,0x52,0x00,0x4E,0x00,0x75,0xEA,0x81,0x7B,0x08,0x45,0x00,0x4C,0x00,0x75,0xE1,0x81,0x7B,0x0C,0x33,0x00,0x32,
                                              0x00,0x75,0xD8,0x81,0x7B,0x10,0x2E,0x00,0x44,0x00,0x75,0xCF,0x81,0x7B,0x14,0x4C,0x00,0x4C,0x00,0x75,0xC6,0x66,0x83,0x7B,0x18,
                                              0x00,0x75,0xBF,0x8B,0x58,0x10,0x8B,0x53,0x3C,0x01,0xDA,0x8B,0x52,0x78,0x01,0xDA,0x8B,0x72,0x20,0x01,0xDE,0x31,0xC9,0x41,0xAD,
                                              0x01,0xD8,0x81,0x38,0x47,0x65,0x74,0x50,0x75,0xF4,0x81,0x78,0x04,0x72,0x6F,0x63,0x41,0x75,0xEB,0x81,0x78,0x08,0x64,0x64,0x72,
                                              0x65,0x75,0xE2,0x81,0x78,0x0B,0x65,0x73,0x73,0x00,0x75,0xD9,0x8B,0x72,0x24,0x01,0xDE,0x66,0x8B,0x0C,0x4E,0x49,0x8B,0x72,0x1C,
                                              0x01,0xDE,0x8B,0x14,0x8E,0x01,0xDA,0x89,0x15, addrGetProcAddress[0],addrGetProcAddress[1],addrGetProcAddress[2],addrGetProcAddress[3],
                                              0x68, strGetModuleHandleW[0],strGetModuleHandleW[1],strGetModuleHandleW[2],strGetModuleHandleW[3],0x53,0xFF,0xD2,0xA3,
                                              addrGetModuleHandleW[0], addrGetModuleHandleW[1], addrGetModuleHandleW[2], addrGetModuleHandleW[3],0xC7,0x05,
                                              isMonoAddress[0], isMonoAddress[1], isMonoAddress[2], isMonoAddress[3],0x00,0x00,0x00,0x00,0x68,
                                              strMonoDll[0],strMonoDll[1],strMonoDll[2],strMonoDll[3],0xFF,0x15,
                                              addrGetModuleHandleW[0], addrGetModuleHandleW[1], addrGetModuleHandleW[2], addrGetModuleHandleW[3],0x85,0xC0,0x0F,0x85,0x13,0x00,
                                              0x00,0x00,0x68, strMonoDLLB[0],strMonoDLLB[1],strMonoDLLB[2],strMonoDLLB[3],0xFF,0x15,
                                              addrGetModuleHandleW[0], addrGetModuleHandleW[1], addrGetModuleHandleW[2], addrGetModuleHandleW[3],0x85,0xC0,0x0F,0x84,0x82,0x00,
                                              0x00,0x00,0xA3, asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],0x68,
                                              strGetDomain[0], strGetDomain[1], strGetDomain[2], strGetDomain[3],0x50,0xFF,0x15,
                                              addrGetProcAddress[0],addrGetProcAddress[1],addrGetProcAddress[2],addrGetProcAddress[3],0x85,0xC0,0x0F,0x84,0x69,0x00,0x00,0x00,
                                              0xC7,0x05,  isMonoAddress[0], isMonoAddress[1], isMonoAddress[2], isMonoAddress[3],0x01,0x00,0x00,0x00,0x56,0x57,0xBE,0x26,0x00,
                                              0x00,0x00,0x8D,0x3D, strGetDomain[0], strGetDomain[1], strGetDomain[2], strGetDomain[3],0x89,0x47,0x22,0x8D,0x04,0x3E,0x50,0xFF,
                                              0x35,asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],0xFF,0x15,
                                              addrGetProcAddress[0],addrGetProcAddress[1],addrGetProcAddress[2],addrGetProcAddress[3],0x83,0xC6,0x22,0x89,0x04,0x3E,0x83,0xC6,
                                              0x04,0x81,0xFE,0xEE,0x01,0x00,0x00,0x75,0xDF,0x5F,0x5E,0xC7,0x05, asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],
                                              0x00,0x00,0x00,0x00,0xFF,0x15, addrGetDomain[0],addrGetDomain[1],addrGetDomain[2],addrGetDomain[3],
                                              0xA3, addrDomain[0],addrDomain[1],addrDomain[2],addrDomain[3],0x50,0xFF,0x15,
                                              addrThreadAttch[0],addrThreadAttch[1],addrThreadAttch[2],addrThreadAttch[3],0x6A,0x00,0x68,
                                              addrCallback[0],addrCallback[1],addrCallback[2],addrCallback[3],0xFF,0x15,
                                              addrDomainForeach[0],addrDomainForeach[1],addrDomainForeach[2],addrDomainForeach[3],0x83,0xC4,0x0C,0xC3,0x68,
                                              addrModuleNameAddress[0], addrModuleNameAddress[1], addrModuleNameAddress[2], addrModuleNameAddress[3],0xFF,0x15,
                                              addrGetModuleHandleW[0], addrGetModuleHandleW[1], addrGetModuleHandleW[2], addrGetModuleHandleW[3],0x68,
                                              addrFunctionNameAddress[0], addrFunctionNameAddress[1], addrFunctionNameAddress[2], addrFunctionNameAddress[3],0x50,0xFF,0x15,
                                              addrGetProcAddress[0],addrGetProcAddress[1],addrGetProcAddress[2],addrGetProcAddress[3],0xA3,
                                              addrNativeResultAddress[0],addrNativeResultAddress[1],addrNativeResultAddress[2],addrNativeResultAddress[3],0xC3,0x55,0x50,0x53,0x8B,0xEC,0x8B,
                                              0x45,0x10,0x50,0xFF,0x15, addrGetImage[0], addrGetImage[1], addrGetImage[2], addrGetImage[3],0x50,0x8B,0x0D,
                                              asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],0x81,0xF9,0x80,0x00,0x00,0x00,0x0F,0x84,0x20,0x00,0x00,0x00,0x89,0x04,
                                              0x8D,addrImagesAddress[0],addrImagesAddress[1],addrImagesAddress[2],addrImagesAddress[3],0xFF,0x15,
                                              addrGetImageName[0],addrGetImageName[1],addrGetImageName[2],addrGetImageName[3],0x8B,0x0D,
                                              asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],0x89,0x04,0x8D,
                                              addrNamesAddress[0], addrNamesAddress[1], addrNamesAddress[2], addrNamesAddress[3],0xFF,0x05,
                                              asmIndexAddress[0],asmIndexAddress[1],asmIndexAddress[2],asmIndexAddress[3],0x83,0xC4,0x08,0x8B,0xE5,0x5B,0x58,0x5D,0xC3,0xC7,0x05,
                                              addrMonoResultAddress[0],addrMonoResultAddress[1],addrMonoResultAddress[2],addrMonoResultAddress[3],0x00,0x00,0x00,0x00,0xFF,0x35,
                                              addrDomain[0],addrDomain[1],addrDomain[2],addrDomain[3],0xFF,0x15,
                                              addrThreadAttch[0],addrThreadAttch[1],addrThreadAttch[2],addrThreadAttch[3],0x68,
                                              addrClassStr[0], addrClassStr[1], addrClassStr[2], addrClassStr[3],0x68,
                                              addrNamespaceStrAddress[0],addrNamespaceStrAddress[1],addrNamespaceStrAddress[2],addrNamespaceStrAddress[3],0xFF,0x35,
                                              addrAddrImagePointerAddress[0],addrAddrImagePointerAddress[1],addrAddrImagePointerAddress[2],addrAddrImagePointerAddress[3],0xFF,0x15,
                                              addrGetClass[0],addrGetClass[1],addrGetClass[2],addrGetClass[3],0x83,0xC4,0x10,0xC3,0xE8,0xCB,0xFF,0xFF,0xFF,0x85,0xC0,0x0F,0x84,0x27,
                                              0x00,0x00,0x00,0x50,0xFF,0x35, addrDomain[0],addrDomain[1],addrDomain[2],addrDomain[3],0xFF,0x15,
                                              addrGetVtable[0],addrGetVtable[1],addrGetVtable[2],addrGetVtable[3],0x83,0xC4,0x08,0x85,0xC0,0x0F,0x84,0x0F,0x00,0x00,0x00,0x50,0xFF,0x15,
                                              addrGetStaticFields[0],addrGetStaticFields[1],addrGetStaticFields[2],addrGetStaticFields[3],0xA3,
                                              addrMonoResultAddress[0],addrMonoResultAddress[1],addrMonoResultAddress[2],addrMonoResultAddress[3],0x83,0xC4,0x04,0xC3,0xE8,0x96,0xFF,0xFF,
                                              0xFF,0x85,0xC0,0x0F,0x84,0x28,0x00,0x00,0x00,0x6A,0xFF,0x68,
                                              addrMemberStr[0],addrMemberStr[1],addrMemberStr[2],addrMemberStr[3],0x50,0xFF,0x15,
                                              addrGetMethod[0],addrGetMethod[1],addrGetMethod[2],addrGetMethod[3],0x83,0xC4,0x0C,0x85,0xC0,0x0F,0x84,0x0F,0x00,0x00,0x00,0x50,0xFF,0x15,
                                              addrComMethod[0],addrComMethod[1],addrComMethod[2],addrComMethod[3],0xA3,
                                              addrMonoResultAddress[0],addrMonoResultAddress[1],addrMonoResultAddress[2],addrMonoResultAddress[3],0x83,0xC4,0x04,0xC3,0xE8,0x60,0xFF,0xFF,
                                              0xFF,0x85,0xC0,0x0F,0x84,0x50,0x00,0x00,0x00,0x68,  addrMemberStr[0],addrMemberStr[1],addrMemberStr[2],addrMemberStr[3],
                                              0x50,0xFF,0x15, addrGetProperty[0],addrGetProperty[1],addrGetProperty[2],addrGetProperty[3],0x83,0xC4,0x08,0x85,0xC0,0x0F,0x84,0x39,0x00,0x00,
                                              0x00,0x50,0x83,0x3D, addrParaAddress[0],addrParaAddress[1],addrParaAddress[2],addrParaAddress[3],0x00,0x0F,0x85,0x0B,0x00,0x00,0x00,0xFF,0x15,
                                              addrGetter[0],addrGetter[1],addrGetter[2],addrGetter[3],0xE9,0x06,0x00,0x00,0x00,0xFF,0x15,
                                              addrSetter[0],addrSetter[1],addrSetter[2],addrSetter[3],0x83,0xC4,0x04,0x85,0xC0,0x0F,0x84,0x0F,0x00,0x00,0x00,0x50,0xFF,0x15,
                                              addrComMethod[0],addrComMethod[1],addrComMethod[2],addrComMethod[3],0xA3,
                                              addrMonoResultAddress[0],addrMonoResultAddress[1],addrMonoResultAddress[2],addrMonoResultAddress[3],0x83,0xC4,0x04,0xC3,0x47,0x65,0x74,0x4D,
                                              0x6F,0x64,0x75,0x6C,0x65,0x48,0x61,0x6E,0x64,0x6C,0x65,0x57,0x00,0x6D,0x00,0x6F,0x00,0x6E,0x00,0x6F,0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C,0x00,
                                              0x00,0x00,0x6D,0x00,0x6F,0x00,0x6E,0x00,0x6F,0x00,0x2D,0x00,0x32,0x00,0x2E,0x00,0x30,0x00,0x2D,0x00,0x62,0x00,0x64,0x00,0x77,0x00,0x67,0x00,0x63,
                                              0x00,0x2E,0x00,0x64,0x00,0x6C,0x00,0x6C,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x67,0x65,0x74,0x5F,0x72,0x6F,0x6F,0x74,0x5F,0x64,0x6F,0x6D,0x61,
                                              0x69,0x6E,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x74,0x68,0x72,0x65,
                                              0x61,0x64,0x5F,0x61,0x74,0x74,0x61,0x63,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x6D,0x6F,0x6E,0x6F,0x5F,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x5F,0x66,0x6F,0x72,0x65,0x61,0x63,0x68,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x61,0x73,0x73,0x65,0x6D,0x62,0x6C,0x79,0x5F,0x67,0x65,0x74,0x5F,0x69,0x6D,
                                              0x61,0x67,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x69,0x6D,0x61,0x67,0x65,0x5F,
                                              0x67,0x65,0x74,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,
                                              0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x76,0x74,0x61,0x62,0x6C,0x65,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x76,0x74,0x61,0x62,0x6C,0x65,0x5F,0x67,
                                              0x65,0x74,0x5F,0x73,0x74,0x61,0x74,0x69,0x63,0x5F,0x66,0x69,0x65,0x6C,0x64,0x5F,0x64,0x61,0x74,0x61,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,
                                              0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x67,0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6F,0x6D,0x70,0x69,0x6C,0x65,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x63,0x6C,0x61,0x73,0x73,0x5F,0x67,0x65,0x74,0x5F,
                                              0x70,0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x66,0x72,0x6F,0x6D,0x5F,0x6E,0x61,0x6D,0x65,0x00,0x00,0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x70,
                                              0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x67,0x65,0x74,0x5F,0x67,0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,0x6F,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                              0x00,0x00,0x00,0x6D,0x6F,0x6E,0x6F,0x5F,0x70,0x72,0x6F,0x70,0x65,0x72,0x74,0x79,0x5F,0x67,0x65,0x74,0x5F,0x73,0x65,0x74,0x5F,0x6D,0x65,0x74,0x68,
                                              0x6F,0x64,0x00,0x00};

                        }

                        try
                        {
                            _plugin.WriteData(_allocMem, asmCodes);
                            _plugin.CallRemoteFunction(_allocMem, 20000);
                            _injected = true;
                        }
                        catch
                        {
                            InnerUtilities.ReleaseMemory(_plugin.BaseProcess, _allocMem);
                            _injected = false;
                        }
                    }
                    else
                    {
                        InnerUtilities.ReleaseMemory(_plugin.BaseProcess, _allocMem);
                        _injected = false;
                    }
                }
            }

            /// <summary>
            /// Indicates that whether the target process supports mono feature.
            /// </summary>
            public bool MonoSupported
            {
                get
                {
                    if (!_injected) return false;
                    try
                    {
                        var q = ReadRemotePtr(_isMonoOffset);
                        if (q == IntPtr.Zero)
                        {
                            return false;
                        }
                        return true;
                    }
                    catch
                    {
                        return false;
                    }

                }
            }

            /// <summary>
            /// Gets the target function address in the specified module.
            /// </summary>
            /// <param name="moduleName">The module contains target function.</param>
            /// <param name="functionName">The function name.</param>
            /// <returns></returns>
            public IntPtr GetFunctionAddress(string moduleName, string functionName)
            {
                if (!_injected) throw new InvalidOperationException("Not enabled.");

                var mBytes = GetStringBytes(moduleName, Encoding.Unicode, false);
                if (mBytes == null)
                {
                    throw new ArgumentException("Invalid moduleName.", "moduleName");
                }
                var fBytes = GetStringBytes(functionName, Encoding.ASCII, false);
                if (fBytes == null)
                {
                    throw new ArgumentException("Invalid functionName.", "functionName");
                }
                _plugin.WriteData(_allocMem + _addrModuleNameOffset, mBytes);
                _plugin.WriteData(_allocMem + _addrFunctionNameOffset, fBytes);

                CallFunction(_callGetFuncOffset);
                return ReadRemotePtr(_addrNativeResultOffset);
            }

            /// <summary>
            /// Gets all mono assemblies in the process root domain.
            /// </summary>
            /// <returns></returns>
            public MonoAssembly[] GetMonoAssemblies() => GetMonoAssembliesCore(false);

            /// <summary>
            /// Gets 'Assembly-CSharp' assembly.
            /// </summary>
            /// <returns></returns>
            public MonoAssembly GetAssemblyCSharp() => GetMonoAssembliesCore(true)[0];

            /// <summary>
            /// Gets the start address of static fields in the specified class.
            /// </summary>
            /// <param name="assembly">The assembly name.</param>
            /// <param name="namespaceName">The namespace name, can be null.</param>
            /// <param name="className">The class name. nested class requests the parent name,  separated by '/'. </param>
            /// <returns></returns>
            public IntPtr GetStaticFields(MonoAssembly assembly, string namespaceName, string className)
            {
                var bytes = EnsureAsmAndNsNameAndClsName(assembly, namespaceName, className);
                _plugin.WriteData(_allocMem + _addrNamespaceStrOffset, bytes);
                WriteRemotePtr(_addrImagePointerOffset, assembly.Pointer);
                CallFunction(_callGetStaticFieldsOffset);
                return ReadRemotePtr(_addrMonoResultOffset);
            }

            /// <summary>
            /// Gets the compiled method address.
            /// </summary>
            /// <param name="assembly">The assembly name.</param>
            /// <param name="namespaceName">The namespace name, can be null.</param>
            /// <param name="className">The class name. nested class requests the parent name,  separated by '/'. </param>
            /// <param name="memberName">The method name.</param>
            /// <returns></returns>
            public IntPtr GetMethodAddress(MonoAssembly assembly, string namespaceName, string className, string memberName)
            {
                var bytes = EnsureMonoAllPara(assembly, namespaceName, className, memberName);
                _plugin.WriteData(_allocMem + _addrNamespaceStrOffset, bytes);
                WriteRemotePtr(_addrImagePointerOffset, assembly.Pointer);
                CallFunction(_callGetMethodOffset);
                return ReadRemotePtr(_addrMonoResultOffset);
            }

            /// <summary>
            /// Gets the address of property's Getter method.
            /// </summary>
            /// <param name="assembly">The assembly name.</param>
            /// <param name="namespaceName">The namespace name, can be null.</param>
            /// <param name="className">The class name. nested class requests the parent name,  separated by '/'. </param>
            /// <param name="memberName">The property name.</param>
            /// <returns></returns>
            public IntPtr GetPropertyGetterAddress(MonoAssembly assembly, string namespaceName, string className, string memberName)
            {
                var bytes = EnsureMonoAllPara(assembly, namespaceName, className, memberName);
                _plugin.WriteData(_allocMem + _addrNamespaceStrOffset, bytes);
                WriteRemotePtr(_addrImagePointerOffset, assembly.Pointer);
                WriteRemotePtr(_addrParaOffset, IntPtr.Zero);
                CallFunction(_callGetPropertyOffset);
                return ReadRemotePtr(_addrMonoResultOffset);
            }

            /// <summary>
            /// Gets the address of property's Setter method.
            /// </summary>
            /// <param name="assembly">The assembly name.</param>
            /// <param name="namespaceName">The namespace name, can be null.</param>
            /// <param name="className">The class name. nested class requests the parent name,  separated by '/'. </param>
            /// <param name="memberName">The property name.</param>
            /// <returns></returns>
            public IntPtr GetPropertySetterAddress(MonoAssembly assembly, string namespaceName, string className, string memberName)
            {
                var bytes = EnsureMonoAllPara(assembly, namespaceName, className, memberName);
                _plugin.WriteData(_allocMem + _addrNamespaceStrOffset, bytes);
                WriteRemotePtr(_addrImagePointerOffset, assembly.Pointer);
                WriteRemotePtr(_addrParaOffset, IntPtr.Zero + 1);
                CallFunction(_callGetPropertyOffset);
                return ReadRemotePtr(_addrMonoResultOffset);
            }

            private MonoAssembly[] GetMonoAssembliesCore(bool findMain)
            {
                EnsureMono();

                var length = _plugin.ReadData<int>(_allocMem + _asmIdxOffset);
                var result = new MonoAssembly[length];
                var step = 4;
                if (_X64)
                {
                    length >>= 3;
                    step = 8;
                }

                var buf = new byte[64];
                for (int i = 0; i < length; i++)
                {
                    _plugin.ReadData(ReadRemotePtr(_addrNamesOffset + step * i), buf, 0, 64);
                    var nameTemp = Encoding.ASCII.GetString(buf);
                    nameTemp = nameTemp.Substring(0, nameTemp.IndexOf('\0'));
                    result[i] = new MonoAssembly(ReadRemotePtr(_addrImagesOffset + step * i), nameTemp);
                    if (findMain && nameTemp.Equals("Assembly-CSharp"))
                    {
                        return new MonoAssembly[] { result[i] };
                    }
                }
                if (findMain) return new MonoAssembly[1];
                return result;
            }

            private IntPtr ReadRemotePtr(int offset)
            {
                return new IntPtr(_X64 ? _plugin.ReadData<long>(_allocMem + offset) : _plugin.ReadData<int>(_allocMem + offset));
            }

            private void WriteRemotePtr(int offset, IntPtr value)
            {
                _plugin.WriteData(_allocMem + offset, _X64 ? value.ToInt64() : value.ToInt32());
            }

            private void CallFunction(int offset)
            {
                var callResult = _plugin.CallRemoteFunction(_allocMem + offset, 20000);
                if (!callResult.Succeed)
                {
                    throw callResult.Exception;
                }
            }

            private void EnsureMono()
            {
                if (!MonoSupported) throw new InvalidOperationException("Not enabled or not mono.");
            }

            private byte[] EnsureMonoAllPara(MonoAssembly assembly, string namespaceName, string className, string memberName)
            {
                var firstBytes = EnsureAsmAndNsNameAndClsName(assembly, namespaceName, className);
                var secondByes = GetStringBytes(memberName, Encoding.ASCII, false);
                if (secondByes == null)
                {
                    throw new ArgumentException("Invalid memberName.", "memberName");
                }
                return firstBytes.Concat(secondByes).ToArray();
            }

            private byte[] EnsureAsmAndNsNameAndClsName(MonoAssembly assembly, string namespaceName, string className)
            {
                EnsureMono();
                if (assembly == null) throw new ArgumentNullException("assembly");

                var nsBytes = GetStringBytes(namespaceName, Encoding.ASCII, true);
                if (nsBytes == null)
                {
                    throw new ArgumentException("Invalid namespaceName.", "namespaceName");
                }

                var cBytes = GetStringBytes(className, Encoding.ASCII, false);

                if (cBytes == null)
                {
                    throw new ArgumentException("Invalid className.", "className");
                }

                return nsBytes.Concat(cBytes).ToArray();
            }

            private byte[] GetStringBytes(string str, Encoding code, bool canBeNull)
            {
                if (str == null)
                {
                    if (canBeNull)
                    {
                        return new byte[64];
                    }
                    return null;
                }

                if (string.IsNullOrWhiteSpace(str)) return null;

                if (str[str.Length - 1] != '\0')
                {
                    str += '\0';
                }
                var result = new byte[64];
                try
                {
                    code.GetBytes(str, 0, str.Length, result, 0);
                    return result;
                }
                catch
                {
                    return null;
                }
            }

            #region IDisposable Support

            ~AdvancedFeature()
            {
                Dispose();
            }

            internal void Dispose()
            {
                if (_injected)
                {
                    Enabled = false;
                }
                _plugin = null;
                GC.SuppressFinalize(this);
            }
            #endregion

        }



        /// <summary>
        /// Represents the allcated memories in the target process.
        /// </summary>
        public sealed class AllocatedMemoryCollection : IEnumerable<IntPtr>
        {
            #region properties & fields

            private ProcessPlugin _plugin;

            private List<IntPtr> _list;

            /// <summary>
            /// Gets the pointer of allocated memory by index.
            /// </summary>
            /// <param name="index">The index</param>
            /// <returns></returns>
            public IntPtr this[int index] => _list[index];

            /// <summary>
            /// Gets a value indicates the count of allocated memories.
            /// </summary>
            public int Count => _list.Count;

            #endregion

            internal AllocatedMemoryCollection(ProcessPlugin plugin)
            {
                _plugin = plugin;
                _list = new List<IntPtr>();
            }

            #region methods

            /// <summary>
            /// Allocates memory in the target process with the specified size.
            /// </summary>
            /// <param name="size">Memory size.</param>
            public IntPtr Allocate(int size) => Allocate(IntPtr.Zero, size);

            /// <summary>
            /// Allocates memory in the target process, which is located at the specified address,  with the specified size.
            /// </summary>
            /// <param name="expectedAddress">The location in where the memory should be allocated.</param>
            /// <param name="size">Memory size.</param>
            /// <returns></returns>
            public IntPtr Allocate(IntPtr expectedAddress, int size)
            {
                var result = InnerUtilities.AllocMemory(_plugin, expectedAddress, size);
                _list.Add(result);
                return result;
            }

            /// <summary>
            /// Free all allocated memories.
            /// </summary>
            public void FreeAll()
            {
                foreach (var item in _list)
                {
                    InnerUtilities.ReleaseMemory(_plugin.BaseProcess, item);
                }
                _list.Clear();
            }

            /// <summary>
            /// Indicates that whether the pointer is exist.
            /// </summary>
            /// <param name="memAddress"></param>
            /// <returns></returns>
            public bool Contains(IntPtr memAddress) => _list.Contains(memAddress);

            /// <summary>
            /// Gets the index of the specified memory.
            /// </summary>
            /// <param name="memAddress">The pointer to the memory.</param>
            /// <returns></returns>
            public int IndexOf(IntPtr memAddress) => _list.IndexOf(memAddress);

            /// <summary>
            /// Free the memory by it's pointer.
            /// </summary>
            /// <param name="memAddress">The specified pointer to be release.</param>
            /// <returns></returns>
            public bool Free(IntPtr memAddress)
            {
                try
                {
                    return _list.Remove(memAddress);
                }
                finally
                {
                    InnerUtilities.ReleaseMemory(_plugin.BaseProcess, memAddress);

                }
            }

            /// <summary>
            /// Free the memory by the specified index.
            /// </summary>
            /// <param name="index">The specified index.</param>
            public void FreeAt(int index)
            {
                var addr = _list[index];
                _list.RemoveAt(index);
                InnerUtilities.ReleaseMemory(_plugin.BaseProcess, addr);
            }

            /// <summary>
            /// Enumerator.
            /// </summary>
            /// <returns></returns>
            public IEnumerator<IntPtr> GetEnumerator() => _list.GetEnumerator();

            /// <summary>
            /// Enumerator.
            /// </summary>
            /// <returns></returns>
            IEnumerator IEnumerable.GetEnumerator() => _list.GetEnumerator();

            #endregion

            #region Internal IDisposable Support

            private bool disposedValue = false;

            ~AllocatedMemoryCollection()
            {
                Dispose();
            }

            internal void Dispose()
            {
                try
                {
                    if (!disposedValue) FreeAll();
                }
                catch { }
                finally
                {
                    _list = null;
                    _plugin = null;
                    disposedValue = true;
                    GC.SuppressFinalize(this);
                }
            }


            #endregion


        }



    }


    /// <summary>
    /// Represents which protection type of memory should be searched.
    /// </summary>
    public enum MemoryProtectionFilter
    {
        /// <summary>
        ///  Not specified.
        /// </summary>
        None = 0,
        /// Enables execute access to the committed region of pages. 
        /// </summary>
        Execute = 0x10,
        /// <summary>
        /// Enables execute or read-only access to the committed region of pages. 
        /// </summary>
        ExecuteRead = 0x20,
        /// <summary>
        /// Enables execute, read-only, or read/write access to the committed region of pages.
        /// </summary>
        ExecuteReadWrite = 0x40,
        /// <summary>
        /// Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object.
        /// </summary>
        ExecuteWriteCopy = 0x80,
        /// <summary>
        /// Enables read-only access to the committed region of pages. 
        /// </summary>
        ReadOnly = 0x02,
        /// <summary>
        /// Enables read-only or read/write access to the committed region of pages.
        /// </summary>
        ReadWrite = 0x04,
        /// <summary>
        /// Enables read-only or copy-on-write access to a mapped view of a file mapping object. 
        /// </summary>
        WriteCopy = 0x08
    }

    /// <summary>
    /// Represent the state of remote calling.
    /// </summary>
    public sealed class RemoteCallState
    {
        /// <summary>
        /// Indicates that if the invoke is succeed.
        /// </summary>
        public bool Succeed { get; }
        /// <summary>
        /// Contains the error infomation, if succeed, this value is set to null.
        /// </summary>
        public string Message { get; }
        /// <summary>
        /// Contains the <see cref="Win32Exception"/> object to reference, if succeed, this value is set to null.
        /// </summary>
        public Win32Exception Exception { get; }
        internal RemoteCallState(bool succeed, string message, Win32Exception exception)
        {
            Succeed = succeed;
            Message = message;
            Exception = exception;
        }
    }

    /// <summary>
    /// Represents the another version of <see cref="ProcessModule"/> class.
    /// </summary>
    public sealed class ProcessModuleAlter
    {
        private FileVersionInfo _fileVersion = null;
        private int _xxhash;

        /// <summary>
        /// Gets the name of the process module.
        /// </summary>
        public string ModuleName { get; }
        /// <summary>
        /// Gets the full path to the module.
        /// </summary>
        public string FileName { get; }
        /// <summary>
        /// Gets the memory address where the module was loaded.
        /// </summary>
        public IntPtr BaseAddress { get; }
        /// <summary>
        /// Gets the memory address for the function that runs when the system loads and runs the module.
        /// </summary>
        public IntPtr EntryPointAddress { get; }
        /// <summary>
        /// Gets the amount of memory that is required to load the module.
        /// </summary>
        public int ModuleMemorySize { get; }

        /// <summary>
        /// Gets version information about the module.
        /// </summary>
        public FileVersionInfo FileVersionInfo
        {
            get
            {
                if (_fileVersion == null)
                {
                    _fileVersion = FileVersionInfo.GetVersionInfo(FileName);
                }
                return _fileVersion;
            }
        }

        internal ProcessModuleAlter(string baseName, string fileName, InnerUtilities.ModuleInfo moduleInfo)
        {
            BaseAddress = moduleInfo.BaseOfDll;
            EntryPointAddress = moduleInfo.EntryPoint;
            ModuleMemorySize = moduleInfo.SizeOfImage;
            FileName = fileName;
            ModuleName = baseName;
        }

        /// <summary>
        /// Converts the name of the module to a string.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => string.Format(CultureInfo.CurrentCulture, "{0} ({1})", base.ToString(), this.ModuleName);

        /// <summary>
        /// Get the XXhash32 value of module.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            if (_xxhash == 0)
            {
                _xxhash = GetModuleHash(FileName);
            }

            return _xxhash;
        }

        /// <summary>
        /// Get the XXhash32 value of module.
        /// </summary>
        /// <param name="path">The full path of module.</param>
        /// <returns></returns>
        public static int GetModuleHash(string path)
        {
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read))
            {
                using (var xxh = new InnerUtilities.XXHash32())
                {
                    xxh.ComputeHash(fs);
                    return (int)xxh.HashUInt32;
                }
            }
        }
    }

    /// <summary>
    /// Represents a mono assembly.
    /// </summary>
    public sealed class MonoAssembly
    {
        internal IntPtr Pointer { get; }

        /// <summary>
        /// The name of the assembly.
        /// </summary>
        public string Name { get; }

        internal MonoAssembly(IntPtr pointer, string name)
        {
            Pointer = pointer;
            Name = name;
        }
    }


    /// <summary>
    /// Provides the extension methods of <see cref="ProcessModule"/> class.
    /// </summary>
    public static class ProcessModuleClassExtensions
    {
        /// <summary>
        /// Compute the XXHash32 value of specified module.
        /// </summary>
        /// <param name="module"><see cref="ProcessModule"/> object.</param>
        /// <returns></returns>
        public static int GetXXHash(this ProcessModule module) => ProcessModuleAlter.GetModuleHash(module.FileName);
    }



    /// <summary>
    /// Represents a byte array finder with the immutable pattern.
    /// </summary>
    public class BytesFinder
    {

        private static readonly ConcurrentBag<int[]> _MoveTablePool = new ConcurrentBag<int[]>();

        #region expressions
        private static readonly ParameterExpression _ExpParamSource = Expression.Parameter(typeof(byte[]), "source");
        private static readonly ParameterExpression _ExpParamSourceIndex = Expression.Parameter(typeof(int), "sourceIndex");
        private static readonly ParameterExpression _ExpParamPatternLength = Expression.Parameter(typeof(int), "patternLength");
        private static readonly ParameterExpression _ExpUnusedParamPattern = Expression.Parameter(typeof(byte[]), "unusedPattern");
        private static readonly BinaryExpression _ExpArrayItemIterator = Expression.ArrayIndex(_ExpParamSource, Expression.PostIncrementAssign(_ExpParamSourceIndex));
        private static readonly ConstantExpression _ExpTrue = Expression.Constant(true, typeof(bool));
        #endregion

        private readonly byte[] _mBytesPattern;
        private readonly Func<byte[], byte[], int, int, bool> _mCompareFunc;
        private readonly int[] _mMoveTable;
        private readonly int _mPatternLength;

        /// <summary>
        /// Initializes a new instance of the <see cref="BytesFinder"/> class for the specified bytes pattern.
        /// </summary>
        /// <param name="pattern">The bytes pattern to seek.</param>
        /// <exception cref="ArgumentException"><paramref name="pattern"/> is null or empty.</exception>
        public BytesFinder(byte[] pattern)
        {
            Ensure_pattern(pattern);
            _mBytesPattern = pattern;
            _mMoveTable = InitializeTable(pattern);
            _mCompareFunc = CompareCore;
            _mPatternLength = pattern.Length;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="BytesFinder"/> class for the specified <see cref="string"/> pattern.
        /// </summary>
        /// <param name="pattern">The <see cref="string"/> pattern to seek.</param>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The length of <paramref name="pattern"/> is 0 or not equal to this value division by 2.
        /// <para>- Or -</para>
        /// Unexpected char in <paramref name="pattern"/>.
        /// </exception>
        public BytesFinder(string pattern)
        {
            if (pattern == null) throw new ArgumentNullException(nameof(pattern), "pattern is null.");
            pattern = pattern.Replace(" ", string.Empty); //remove placeholder
            var strLen = pattern.Length;
            if (strLen == 0 || (strLen & 1) == 1) throw new FormatException("The length of pattern is 0 or not equal to this value division by 2.");
            _mPatternLength = strLen >> 1;
            var maxMove = _mPatternLength - 1;
            _mMoveTable = GetTableFormBag(_mPatternLength);

            Expression exp = _ExpTrue;

            #region  generates move table and comparison expression
            unsafe
            {
                fixed (int* next = _mMoveTable)
                {
                    fixed (char* patt = pattern)
                    {
                        var idx = 0;
                        while (idx < strLen)
                        {
                            var badMove = maxMove - (idx >> 1);
                            var currentChar = patt[idx++];
                            var nextChar = patt[idx++];
                            int nextDigit;
                            if (currentChar == '?')
                            {
                                if (nextChar == '?') //??
                                {
                                    SetMultiBadMove(next, badMove, 0, 1); //update move table
                                                                          //update expression
                                    exp = Expression.AndAlso(
                                        exp,
                                        Expression.Block(
                                            Expression.PreIncrementAssign(_ExpParamSourceIndex),
                                            _ExpTrue));
                                }
                                else //?a
                                {
                                    nextDigit = GetHexDigit(nextChar);
                                    SetMultiBadMove(next, badMove, nextDigit, 0x10); //update move table
                                    exp = MakeExpCmpDigit(exp, nextDigit, 0x0F); //update expression
                                }
                            }
                            else
                            {
                                var firstDigit = GetHexDigit(currentChar) << 4;

                                if (nextChar == '?') //a?
                                {
                                    SetMultiBadMove(next, badMove, firstDigit, 1); //update move table
                                    exp = MakeExpCmpDigit(exp, firstDigit, 0xF0); //update expression
                                }
                                else //ab
                                {
                                    nextDigit = GetHexDigit(nextChar);
                                    var hexNum = (byte)(firstDigit | nextDigit);
                                    next[hexNum] = badMove; //update move table
                                                            //update expression
                                    exp = Expression.AndAlso(
                                            exp,
                                            Expression.Equal(
                                                _ExpArrayItemIterator,
                                                Expression.Constant(hexNum, typeof(byte))));
                                }
                            }
                        }
                    }
                }
            }
            #endregion

            _mCompareFunc = Expression.Lambda<Func<byte[], byte[], int, int, bool>>(
                exp, _ExpParamSource, _ExpUnusedParamPattern, _ExpParamSourceIndex, _ExpParamPatternLength)
                .Compile();
        }

        #region instance methods

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the pattern in the specified bytes.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <returns>The zero-based index position of the occurrence if the pattern is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        public int FindIndexIn(byte[] source)
        {
            Ensure_source(source);
            return InnerFindIndex(source, _mBytesPattern, _mMoveTable, _mCompareFunc, _mPatternLength, 0, source.Length);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the pattern in the specified bytes.
        /// The search starts at the specified position.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <returns>The zero-based index position of the occurrence if the pattern is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// </exception>
        public int FindIndexIn(byte[] source, int startIndex)
        {
            Ensure_source_startIndex(source, startIndex);
            return InnerFindIndex(source, _mBytesPattern, _mMoveTable, _mCompareFunc, _mPatternLength, startIndex, source.Length);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the pattern in the specified bytes.
        /// The search starts at the specified position and examines a specified number of <see cref="byte"/> positions.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <param name="count">The number of <see cref="byte"/> positions to examine.</param>
        /// <returns>The zero-based index position of the occurrence if the pattern is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is less than or equal to 0.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is greater than the length of source minus <paramref name="startIndex"/>.
        /// </exception>
        public int FindIndexIn(byte[] source, int startIndex, int count)
        {
            Ensure_source_startIndex_count(source, startIndex, count);
            return InnerFindIndex(source, _mBytesPattern, _mMoveTable, _mCompareFunc, _mPatternLength, startIndex, count);
        }

        #endregion

        #region static methods

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The bytes pattern to seek.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="source"/> is null or empty.
        /// <para>- Or -</para>
        /// <paramref name="pattern"/> is null or empty.
        /// </exception>
        public static int FindIndex(byte[] source, byte[] pattern)
        {
            Ensure_source(source);
            Ensure_pattern(pattern);
            return RentTableAndFindIndex(source, pattern, 0, source.Length);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// The search starts at the specified position.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The bytes pattern to seek.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="source"/> is null or empty.
        /// <para>- Or -</para>
        /// <paramref name="pattern"/> is null or empty.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// </exception>
        public static int FindIndex(byte[] source, byte[] pattern, int startIndex)
        {
            Ensure_pattern(pattern);
            Ensure_source_startIndex(source, startIndex);
            return RentTableAndFindIndex(source, pattern, startIndex, source.Length);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// The search starts at the specified position and examines a specified number of <see cref="byte"/> positions.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The bytes pattern to seek.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <param name="count">The number of <see cref="byte"/> positions to examine.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="source"/> is null or empty.
        /// <para>- Or -</para>
        /// <paramref name="pattern"/> is null or empty.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is less than or equal to 0.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is greater than the length of source minus <paramref name="startIndex"/>.
        /// </exception>
        public static int FindIndex(byte[] source, byte[] pattern, int startIndex, int count)
        {
            Ensure_pattern(pattern);
            Ensure_source_startIndex_count(source, startIndex, count);
            return RentTableAndFindIndex(source, pattern, startIndex, count);
        }


        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The <see cref="string"/> pattern to seek.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The length of <paramref name="pattern"/> is 0 or not equal to this value division by 2.
        /// <para>- Or -</para>
        /// Unexpected char in <paramref name="pattern"/>.
        /// </exception>
        public static int FindIndex(byte[] source, string pattern)
        {
            Ensure_source(source);
            return (new BytesFinder(pattern)).FindIndexIn(source);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// The search starts at the specified position.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The <see cref="string"/> pattern to seek.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The length of <paramref name="pattern"/> is 0 or not equal to this value division by 2.
        /// <para>- Or -</para>
        /// Unexpected char in <paramref name="pattern"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// </exception>
        public static int FindIndex(byte[] source, string pattern, int startIndex)
        {
            Ensure_source_startIndex(source, startIndex);
            return (new BytesFinder(pattern)).FindIndexIn(source, startIndex);
        }

        /// <summary>
        /// Reports the zero-based index of the first occurrence of the specified pattern in the specified bytes source.
        /// The search starts at the specified position and examines a specified number of <see cref="byte"/> positions.
        /// </summary>
        /// <param name="source">The bytes to search for an occurrence.</param>
        /// <param name="pattern">The <see cref="string"/> pattern to seek.</param>
        /// <param name="startIndex">The search starting position.</param>
        /// <param name="count">The number of <see cref="byte"/> positions to examine.</param>
        /// <returns>The zero-based index position of the occurrence if the <paramref name="pattern"/> is found, otherwise, -1.</returns>
        /// <exception cref="ArgumentException"><paramref name="source"/> is null or empty.</exception>
        /// <exception cref="ArgumentNullException"><paramref name="pattern"/> is null.</exception>
        /// <exception cref="FormatException">
        /// The length of <paramref name="pattern"/> is 0 or not equal to this value division by 2.
        /// <para>- Or -</para>
        /// Unexpected char in <paramref name="pattern"/>.
        /// </exception>
        /// <exception cref="ArgumentOutOfRangeException">
        /// <paramref name="startIndex"/> is less than 0.
        /// <para>- Or -</para>
        /// <paramref name="startIndex"/> is greater than or equal to the length of <paramref name="source"/>.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is less than or equal to 0.
        /// <para>- Or -</para>
        /// <paramref name="count"/> is greater than the length of source minus <paramref name="startIndex"/>.
        /// </exception>
        public static int FindIndex(byte[] source, string pattern, int startIndex, int count)
        {
            Ensure_source_startIndex_count(source, startIndex, count);
            return (new BytesFinder(pattern)).FindIndexIn(source, startIndex, count);
        }


        #endregion

        #region private static methods

        private static int RentTableAndFindIndex(byte[] source, byte[] pattern, int startIndex, int count)
        {
            var moveTable = InitializeTable(pattern);
            try
            {
                return InnerFindIndex(source, pattern, moveTable, CompareCore, pattern.Length, startIndex, count);
            }
            finally
            {
                _MoveTablePool.Add(moveTable);
            }
        }

        private static int[] InitializeTable(byte[] pattern)
        {
            var pattLen = pattern.Length;
            var pattMaxIdx = pattLen - 1;
            var moveTable = GetTableFormBag(pattLen);
            unsafe
            {
                fixed (int* next = moveTable)
                {
                    fixed (byte* patt = pattern)
                    {
                        for (int i = 0; i < pattLen; i++)
                        {
                            next[patt[i]] = pattMaxIdx - i;
                        }
                        return moveTable;
                    }
                }
            }
        }

        private static int InnerFindIndex(byte[] source, byte[] pattern, int[] moveTable, Func<byte[], byte[], int, int, bool> compareFunc, int patternLength, int startIndex, int count)
        {
            var pattMaxIdx = patternLength - 1;
            var maxLen = count - patternLength + 1;
            unsafe
            {
                fixed (int* next = moveTable)
                {
                    fixed (byte* src = source)
                    {
                        while (startIndex < maxLen)
                        {
                            var mov = next[src[startIndex + pattMaxIdx]];
                            if (mov < patternLength)
                            {
                                startIndex += mov;

                                if (compareFunc(source, pattern, startIndex, patternLength)) return startIndex;
                                ++startIndex;
                                continue;
                            }
                            else
                            {
                                startIndex += patternLength;
                            }
                        }
                        return -1;
                    }
                }
            }
        }

        private static bool CompareCore(byte[] source, byte[] pattern, int startIndex, int patternLength)
        {
            unsafe
            {
                fixed (byte* src = source, patt = pattern)
                {
                    for (var i = 0; i < patternLength; i++)
                    {
                        if (src[startIndex + i] != patt[i])
                        {
                            return false;
                        }
                    }
                    return true;
                }
            }
        }

        private static void Ensure_source(byte[] source)
        {
            if (source == null || source.Length == 0) throw new ArgumentException("source is null or empty.", nameof(source));
        }

        private static void Ensure_pattern(byte[] pattern)
        {
            if (pattern == null || pattern.Length == 0) throw new ArgumentException("pattern is null or empty.", nameof(pattern));
        }

        private static void Ensure_source_startIndex(byte[] source, int startIndex)
        {
            Ensure_source(source);
            if (startIndex < 0) throw new ArgumentOutOfRangeException(nameof(startIndex), "startIndex is less than 0.");
            if (startIndex >= source.Length) throw new ArgumentOutOfRangeException(nameof(startIndex), "startIndex is greater than or equal to the length of source.");
        }

        private static void Ensure_source_startIndex_count(byte[] source, int startIndex, int count)
        {
            Ensure_source_startIndex(source, startIndex);
            if (count <= 0) throw new ArgumentOutOfRangeException(nameof(startIndex), "count is less than or equal to 0.");
            if (count > source.Length - startIndex) throw new ArgumentOutOfRangeException(nameof(count), "count is greater than the length of source minus startIndex.");
        }

        private static int[] GetTableFormBag(int patternLength)
        {
            var result = _MoveTablePool.TryTake(out var item) ? item : new int[256];
            unsafe
            {
                fixed (int* buffer = result)
                {
                    for (int i = 0; i < 256; i++)
                    {
                        buffer[i] = patternLength;
                    }
                }
            }
            return result;
        }

        private static int GetHexDigit(char number)
        {
            if (number >= '0' && number <= '9')
            {
                return number - '0';
            }
            else if ((number >= 'a' && number <= 'f') ||
                     (number >= 'A' && number <= 'F'))
            {
                return (number & 7) + 9;     //  'a'=0x61, 'A'=0x41
            }
            throw new FormatException("Unexpected char in pattern.");
        }

        private unsafe static void SetMultiBadMove(int* moveTable, int badMove, int start, int step)
        {
            for (int i = start; i < 256; i += step)
            {
                moveTable[i] = badMove;
            }
        }

        private static Expression MakeExpCmpDigit(Expression exp, int digit, int mask) => Expression.AndAlso(
            exp,
            Expression.Equal(
                Expression.And(
                    _ExpArrayItemIterator,
                    Expression.Constant((byte)mask, typeof(byte))),
                Expression.Constant((byte)digit, typeof(byte))));


        #endregion

    }

    internal static class InnerUtilities
    {
        public const int INFINITE_INT = -1;

        public static readonly NativeMethods.SysInfo SystemInfo = new NativeMethods.SysInfo();


        static InnerUtilities()
        {
            NativeMethods.GetSystemInfo(SystemInfo);
        }


        public static Process GetProcessByWindow(string windowName, string windowClass)
        {
            var hWnd = NativeMethods.FindWindowEx(IntPtr.Zero, IntPtr.Zero, windowClass, windowName);

            if (hWnd == IntPtr.Zero)
            {
                var error = Marshal.GetLastWin32Error();
                if (error == 2) return null;     //2 = Not Founded
                throw new Win32Exception(error);
            }
            NativeMethods.GetWindowThreadProcessId(hWnd, out var pid);
            return Process.GetProcessById(pid);
        }

        public static string GetWindowClassByHandle(Process process)
        {
            var sb = StringBuilderPool.Rent();
            if (NativeMethods.GetClassName(process.MainWindowHandle, sb, 2048) == 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            var className = sb.ToString();
            StringBuilderPool.Return(sb);
            return className;
        }

        public static ProcessModuleAlter GetModuleByName(Process process, string moduleName)
        {
            if (string.IsNullOrWhiteSpace(moduleName)) throw new ArgumentException("moduleName is null or empty.", "moduleName");

            var hr = new HandleRef(process, process.Handle);

            var size = 0;
            if (!NativeMethods.EnumProcessModulesEx(hr, null, 0, ref size, NativeMethods.ModuleFilter.LIST_MODULES_ALL))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var modules = new IntPtr[size / IntPtr.Size];
            if (!NativeMethods.EnumProcessModulesEx(hr, modules, size, ref size, NativeMethods.ModuleFilter.LIST_MODULES_ALL))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            var sb = StringBuilderPool.Rent();
            var moduleInfo = ModuleInfoPool.Rent();
            try
            {
                foreach (var item in modules)
                {
                    if (NativeMethods.GetModuleBaseName(hr, item, sb, 2048) == 0)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());

                    }
                    if (!moduleName.Equals(sb.ToString()))
                    {
                        continue;
                    }

                    if (NativeMethods.GetModuleFileNameEx(hr, item, sb, 2048) == 0)
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    if (!NativeMethods.GetModuleInformation(hr, item, moduleInfo, ModuleInfo.Size))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }
                    return new ProcessModuleAlter(moduleName, sb.ToString(), moduleInfo);
                }
                return null;
            }
            finally
            {
                StringBuilderPool.Return(sb);
                ModuleInfoPool.Return(moduleInfo);
            }
        }

        public static T ReadData<T>(Process process, IntPtr address) where T : unmanaged
        {
            T data = default;
            unsafe
            {
                void* p = &data;
                AccessMemory(process, address, p, new IntPtr(Marshal.SizeOf<T>()), NativeMethods.ReadProcessMemory);
            }
            return data;
        }

        public static T[] ReadData<T>(Process process, IntPtr address, int count) where T : unmanaged
        {
            var data = new T[count];
            ReadData<T>(process, address, data, 0, count);
            return data;
        }

        public static void ReadData<T>(Process process, IntPtr address, T[] data, int startIndex, int count) where T : unmanaged
        {
            EnsureDateIndexCount(data, startIndex, count);
            unsafe
            {
                fixed (void* p = data)
                {
                    AccessMemory(process, address, p, new IntPtr(Marshal.SizeOf<T>() * (count - startIndex)), NativeMethods.ReadProcessMemory);
                }

            }
        }

        public static void WriteData<T>(Process process, IntPtr address, params T[] data) where T : unmanaged
        {
            WriteData<T>(process, address, data, 0, data.Length);
        }

        public static void WriteData<T>(Process process, IntPtr address, T[] data, int startIndex, int count) where T : unmanaged
        {
            EnsureDateIndexCount(data, startIndex, count);
            unsafe
            {
                fixed (void* p = data)
                {
                    AccessMemory(process, address, p, new IntPtr(Marshal.SizeOf<T>() * (count - startIndex)), NativeMethods.WriteProcessMemory);
                }
            }

        }

        public static IntPtr AllocMemory(ProcessPlugin plugin, IntPtr address, int size)
        {
            NativeMethods.AllocationOption options = NativeMethods.AllocationOption.Commit;
            if (address != IntPtr.Zero)
            {
                if (!plugin.Is64BitProcess)
                {
                    address = IntPtr.Zero;
                }
                else
                {
                    address = ScanNearAddress(plugin, address, size);
                    if (address != IntPtr.Zero)
                    {
                        options |= NativeMethods.AllocationOption.Reserve;
                    }
                }
            }

            var hr = new HandleRef(plugin.BaseProcess, plugin.BaseProcess.Handle);
            var result = NativeMethods.VirtualAllocEx(hr, address, new IntPtr(size), options, NativeMethods.MemoryProtection.ExecuteReadWrite);
            if (result == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return result;
        }

        public static void ReleaseMemory(Process process, IntPtr address)
        {
            try
            {
                var hr = new HandleRef(process, process.Handle);
                NativeMethods.VirtualFreeEx(hr, address, IntPtr.Zero, NativeMethods.FreeOption.Release);
            }
            catch { }
        }

        public static IntPtr ScanByteArray(Process process, byte[] pattern, Func<byte[], byte[], int> checker, IntPtr addressStart, IntPtr addressEnd, MemoryProtectionFilter filter)
        {
            var hr = new HandleRef(process, process.Handle);
            unsafe
            {
                var address = addressStart;
                var memInfo = new NativeMethods.MemoryBasicInfo();
                var miSize = NativeMethods.MemoryBasicInfo.Size;
                while (address.ToPointer() < addressEnd.ToPointer())
                {
                    if (!NativeMethods.VirtualQueryEx(hr, address, memInfo, miSize))
                    {
                        return IntPtr.Zero;
                    }
                    if (memInfo.State.HasFlag(NativeMethods.MemoryState.Commit) &&
                        !memInfo.Protect.HasFlag(NativeMethods.MemoryProtection.Guard) &&
                        !memInfo.Protect.HasFlag(NativeMethods.MemoryProtection.NoAccess) &&
                         memInfo.Protect.HasFlag((NativeMethods.MemoryProtection)filter))
                    {
                        var buffer = ReadData<byte>(process, memInfo.BaseAddress, memInfo.RegionSize.ToInt32());
                        var result = checker(buffer, pattern);
                        if (result != -1)
                        {
                            return memInfo.BaseAddress + result;
                        }
                    }
                    address = new IntPtr(memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64());
                }
            }
            return IntPtr.Zero;
        }

        private static IntPtr ScanNearAddress(ProcessPlugin plugin, IntPtr addressToRef, int size)
        {
            var hr = new HandleRef(plugin.BaseProcess, plugin.BaseProcess.Handle);

            var minMem = SystemInfo.MinimumApplicationAddress.ToInt64();
            var maxMem = plugin._maxMemory.ToInt64();


            var minAddr = addressToRef.ToInt64() - 0x70000000;
            var maxAddr = addressToRef.ToInt64() + 0x70000000;

            if (minAddr > maxMem || minAddr < minMem) minAddr = minMem;

            if (maxAddr < minMem || maxAddr > maxMem) maxAddr = maxMem;

            var nowRef = minAddr;

            var targetAddr = addressToRef.ToInt64();
            var allocGranularity = SystemInfo.AllocationGranularity;
            var lastResult = 0L;

            var memInfo = new NativeMethods.MemoryBasicInfo();
            var miSize = NativeMethods.MemoryBasicInfo.Size;

            unsafe
            {
                while (NativeMethods.VirtualQueryEx(hr, new IntPtr(nowRef), memInfo, miSize))
                {
                    var memBase = memInfo.BaseAddress.ToInt64();

                    if (memBase > maxAddr) break;

                    var regionSize = memInfo.RegionSize.ToInt64();

                    if (memInfo.State == NativeMethods.MemoryState.Free &&
                        regionSize > size)
                    {
                        var x = memBase;
                        var baseleft = memBase % allocGranularity;

                        if (baseleft != 0)
                        {
                            var offset = allocGranularity - baseleft;
                            var tof = regionSize - offset;
                            if (tof >= size)
                            {
                                x += offset;
                                if (x < targetAddr)
                                {
                                    x += tof - size;
                                    if (x > targetAddr) x = targetAddr;
                                    x -= x % allocGranularity;
                                }
                                if (Math.Abs(x - targetAddr) < Math.Abs(lastResult - targetAddr)) lastResult = x;
                            }
                        }
                        else
                        {
                            if (x < targetAddr)
                            {
                                x += regionSize - size;
                                if (x > targetAddr) x = targetAddr;
                                x -= x % allocGranularity;
                            }
                            if (Math.Abs(x - targetAddr) < Math.Abs(lastResult - targetAddr)) lastResult = x;
                        }
                    }

                    var regionLeft = regionSize % allocGranularity;

                    if (regionLeft != 0) regionSize += allocGranularity - regionLeft;

                    var oldRef = nowRef;
                    nowRef = memBase + regionSize;
                    if (nowRef > maxAddr || oldRef > nowRef)
                    {
                        break;
                    }
                }
            }
            return new IntPtr(lastResult);
        }

        public static RemoteCallState CallRemoteFunc(Process process, IntPtr address, int timeOut)
        {
            var hr = new HandleRef(process, process.Handle);
            var succeed = false;
            string Msg = null;
            Win32Exception ex = null;
            using (var rhandle = NativeMethods.CreateRemoteThread(hr, IntPtr.Zero, IntPtr.Zero, address, IntPtr.Zero, NativeMethods.ThreadCreationFlags.None, out _))
            {
                if (rhandle.IsInvalid)
                {
                    Msg = "Failed to create thread.";
                    ex = new Win32Exception(Marshal.GetLastWin32Error());
                }

                switch (NativeMethods.WaitForSingleObject(rhandle, timeOut))
                {
                    case NativeMethods.WaitObjectResult.WAIT_FAILED:
                        ex = new Win32Exception(Marshal.GetLastWin32Error());
                        Msg = "Unanticipated exception.";
                        break;
                    case NativeMethods.WaitObjectResult.WAIT_TIMEOUT:
                        Msg = "Timeout.";
                        if (!NativeMethods.TerminateThread(rhandle, 0))
                        {
                            ex = new Win32Exception(Marshal.GetLastWin32Error());
                            Msg += "\nAnd failed to kill remote thread.";
                        }
                        break;
                    default:
                        succeed = true;
                        break;
                }
                return new RemoteCallState(succeed, Msg, ex);
            }
        }


        private unsafe delegate bool AccMemDel(HandleRef hProcess, IntPtr lpBaseAddress, void* lpBuffer, IntPtr nSize, out IntPtr lpNumberOfBytes);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Interoperability", "CA1404:CallGetLastErrorImmediatelyAfterPInvoke")]
        private unsafe static void AccessMemory(Process process, IntPtr address, [In] void* data, IntPtr size, AccMemDel action)
        {
            var hr = new HandleRef(process, process.Handle);

            if (!action(hr, address, data, size, out _))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == NativeMethods.ERROR_NOACCESS)
                {
                    if (!NativeMethods.VirtualProtectEx(hr, address, size, NativeMethods.MemoryProtection.ExecuteReadWrite, out var oldProtect))
                    {
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                    }

                    try
                    {
                        if (!action(hr, address, data, size, out _))
                        {
                            throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                    }
                    finally
                    {
                        NativeMethods.VirtualProtectEx(hr, address, size, oldProtect, out var _);
                    }
                }
                else
                {
                    throw new Win32Exception(
                        error,
                        $"{action.Method.Name}:  Process={{{hr.Handle.ToString("X")}}}, Address={{{address.ToString("X")}}}");
                }
            }
        }


        private static void EnsureDateIndexCount<T>(T[] data, int startIndex, int count)
        {
            if (data == null || data.Length < 1) throw new ArgumentException("data is null or empty.", "data");
            if (count < 1 || startIndex < 0 || data.Length - startIndex < count)
            {
                throw new ArgumentOutOfRangeException("startIndex is less than 0 or count is less than 1 or data length minus startIndex is less than count.");
            }
        }

        /// <summary>
        /// Represents the class which provides a implementation of the xxHash32 algorithm.
        /// </summary>
        ///<threadsafety static="true" instance="false"/>   
        public sealed class XXHash32 : HashAlgorithm
        {
            private const uint PRIME32_1 = 2654435761U;
            private const uint PRIME32_2 = 2246822519U;
            private const uint PRIME32_3 = 3266489917U;
            private const uint PRIME32_4 = 668265263U;
            private const uint PRIME32_5 = 374761393U;

            private static uint FuncGetLittleEndianUInt32(byte[] buffer, int index)
            {
                unsafe
                {
                    fixed (byte* array = buffer)
                    {
                        return *(uint*)(array + index);
                    }
                }
            }

            private static uint FuncGetFinalHashUInt32(uint i) => (i & 0x000000FFU) << 24 | (i & 0x0000FF00U) << 8 | (i & 0x00FF0000U) >> 8 | (i & 0xFF000000U) >> 24;

            private uint _Seed32;

            private uint _ACC32_1;
            private uint _ACC32_2;
            private uint _ACC32_3;
            private uint _ACC32_4;

            private uint _Hash32;


            private int _RemainingLength;
            private long _TotalLength = 0;
            private int _CurrentIndex;
            private byte[] _CurrentArray;

            /// <summary>
            /// Initializes a new instance of the <see cref="XXHash32"/> class by default seed(0).
            /// </summary>
            public XXHash32() => Initialize(0);

            /// <summary>
            /// Initializes a new instance of the <see cref="XXHash32"/> class, and sets the <see cref="Seed"/> to the specified value.
            /// </summary>
            /// <param name="seed">Represent the seed to be used for xxHash32 computing.</param>
            public XXHash32(uint seed) => Initialize(seed);

            /// <summary>
            /// Gets the <see cref="uint"/> value of the computed hash code.
            /// </summary>
            /// <exception cref="InvalidOperationException">Hash computation has not yet completed.</exception>
            public uint HashUInt32 => State == 0 ? _Hash32 : throw new InvalidOperationException("Hash computation has not yet completed.");

            /// <summary>
            /// Gets or sets the value of seed used by xxHash32 algorithm.
            /// </summary>
            /// <exception cref="InvalidOperationException">Hash computation has not yet completed.</exception>
            public uint Seed
            {
                get => _Seed32;
                set
                {

                    if (value != _Seed32)
                    {
                        if (State != 0) throw new InvalidOperationException("Hash computation has not yet completed.");
                        _Seed32 = value;
                        Initialize();
                    }
                }
            }

            /// <summary>
            /// Initializes this instance for new hash computing.
            /// </summary>
            public override void Initialize()
            {
                _ACC32_1 = _Seed32 + PRIME32_1 + PRIME32_2;
                _ACC32_2 = _Seed32 + PRIME32_2;
                _ACC32_3 = _Seed32 + 0;
                _ACC32_4 = _Seed32 - PRIME32_1;
            }

            /// <summary>
            /// Routes data written to the object into the hash algorithm for computing the hash.
            /// </summary>
            /// <param name="array">The input to compute the hash code for.</param>
            /// <param name="ibStart">The offset into the byte array from which to begin using data.</param>
            /// <param name="cbSize">The number of bytes in the byte array to use as data.</param>
            protected override void HashCore(byte[] array, int ibStart, int cbSize)
            {
                if (State != 1) State = 1;
                var size = cbSize - ibStart;
                _RemainingLength = size & 15;
                if (cbSize >= 16)
                {
                    var limit = size - _RemainingLength;
                    do
                    {
                        _ACC32_1 = Round32(_ACC32_1, FuncGetLittleEndianUInt32(array, ibStart));
                        _ACC32_2 = Round32(_ACC32_2, FuncGetLittleEndianUInt32(array, ibStart + 4));
                        _ACC32_3 = Round32(_ACC32_3, FuncGetLittleEndianUInt32(array, ibStart + 8));
                        _ACC32_4 = Round32(_ACC32_4, FuncGetLittleEndianUInt32(array, ibStart + 12));
                        ibStart += 16;
                    } while (ibStart < limit);
                }
                _TotalLength += cbSize;

                if (_RemainingLength != 0)
                {
                    _CurrentArray = array;
                    _CurrentIndex = ibStart;
                }
            }

            /// <summary>
            /// Finalizes the hash computation after the last data is processed by the cryptographic stream object.
            /// </summary>
            /// <returns>The computed hash code.</returns>
            protected override byte[] HashFinal()
            {
                if (_TotalLength >= 16)
                {
                    _Hash32 = RotateLeft32_1(_ACC32_1) + RotateLeft32_7(_ACC32_2) + RotateLeft32_12(_ACC32_3) + RotateLeft32_18(_ACC32_4);

                }
                else
                {
                    _Hash32 = _Seed32 + PRIME32_5;
                }

                _Hash32 += (uint)_TotalLength;

                while (_RemainingLength >= 4)
                {
                    _Hash32 = RotateLeft32_17(_Hash32 + FuncGetLittleEndianUInt32(_CurrentArray, _CurrentIndex) * PRIME32_3) * PRIME32_4;

                    _CurrentIndex += 4;
                    _RemainingLength -= 4;
                }
                unsafe
                {
                    fixed (byte* arrayPtr = _CurrentArray)
                    {
                        while (_RemainingLength-- >= 1)
                        {
                            _Hash32 = RotateLeft32_11(_Hash32 + arrayPtr[_CurrentIndex++] * PRIME32_5) * PRIME32_1;
                        }
                    }
                }
                _Hash32 = (_Hash32 ^ (_Hash32 >> 15)) * PRIME32_2;
                _Hash32 = (_Hash32 ^ (_Hash32 >> 13)) * PRIME32_3;
                _Hash32 ^= _Hash32 >> 16;

                _TotalLength = State = 0;

                return BitConverter.GetBytes(FuncGetFinalHashUInt32(_Hash32));
            }

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint Round32(uint input, uint value) => RotateLeft32_13(input + (value * PRIME32_2)) * PRIME32_1;

            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_1(uint value) => (value << 1) | (value >> 31); //_ACC32_1
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_7(uint value) => (value << 7) | (value >> 25); //_ACC32_2
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_11(uint value) => (value << 11) | (value >> 21);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_12(uint value) => (value << 12) | (value >> 20);// _ACC32_3
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_13(uint value) => (value << 13) | (value >> 19);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_17(uint value) => (value << 17) | (value >> 15);
            [MethodImpl(MethodImplOptions.AggressiveInlining)]
            private static uint RotateLeft32_18(uint value) => (value << 18) | (value >> 14); //_ACC32_4

            private void Initialize(uint seed)
            {
                HashSizeValue = 32;
                _Seed32 = seed;
                Initialize();
            }

        }

        private static class StringBuilderPool
        {
            private static readonly ConcurrentBag<StringBuilder> _Pool;

            static StringBuilderPool() => _Pool = new ConcurrentBag<StringBuilder>();

            public static StringBuilder Rent() => _Pool.TryTake(out var obj) ? obj : new StringBuilder(1024);

            public static void Return(StringBuilder sb)
            {
                sb.Clear();
                _Pool.Add(sb);
            }
        }

        private static class ModuleInfoPool
        {
            private static readonly ConcurrentBag<ModuleInfo> _Pool;

            static ModuleInfoPool() => _Pool = new ConcurrentBag<ModuleInfo>();

            public static ModuleInfo Rent() => _Pool.TryTake(out var obj) ? obj : new ModuleInfo();

            public static void Return(ModuleInfo moduleInfo)
            {
                _Pool.Add(moduleInfo);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public sealed class ModuleInfo
        {
            public readonly IntPtr BaseOfDll = IntPtr.Zero;
            public readonly int SizeOfImage = 0;
            public readonly IntPtr EntryPoint = IntPtr.Zero;

            public static readonly int Size = Marshal.SizeOf<ModuleInfo>();

        }

        public static class NativeMethods
        {
            [DllImport("user32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            public static extern IntPtr FindWindowEx(IntPtr hWndParent, IntPtr hWndChildAfter, string lpszClass, string lpszWindow);

            [DllImport("user32.dll", CallingConvention = CallingConvention.Winapi)]
            public static extern int GetWindowThreadProcessId(IntPtr hWnd, [Out] out int lpdwProcessId);

            [DllImport("user32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            public static extern int GetClassName(IntPtr hWnd, [In, Out] StringBuilder lpClassName, int nMaxCount);

            [DllImport("psapi.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool EnumProcessModulesEx(HandleRef hProcess,
                [MarshalAs(UnmanagedType.LPArray)] [In][Out] IntPtr[] lphModule,
                int cb,
                [In, Out] ref int lpcbNeeded,
                ModuleFilter dwFilterFlag);

            [DllImport("msvcrt.dll", EntryPoint = "memcmp", CallingConvention = CallingConvention.Cdecl)]
            public static extern int Memcmp(byte[] b1, byte[] b2, int count);


            [DllImport("psapi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            public static extern int GetModuleBaseName(HandleRef hProcess, IntPtr hModule, [In, Out] StringBuilder lpBaseName, int nSize);

            [DllImport("psapi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            public static extern int GetModuleFileNameEx(HandleRef hProcess, IntPtr hModule, [In, Out] StringBuilder lpFilename, int nSize);

            [DllImport("psapi.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool GetModuleInformation(HandleRef processHandle, IntPtr moduleHandle, [In, Out] ModuleInfo ntModuleInfo, int size);

            [DllImport("Kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public unsafe static extern bool ReadProcessMemory(HandleRef hProcess, IntPtr lpBaseAddress, [In, Out] void* lpBuffer, [MarshalAs(UnmanagedType.SysInt)]IntPtr nSize, [Out, Optional, MarshalAs(UnmanagedType.SysInt)] out IntPtr lpNumberOfBytesRead);

            [DllImport("Kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public unsafe static extern bool WriteProcessMemory(HandleRef hProcess, IntPtr lpBaseAddress, [In, Out] void* lpBuffer, [MarshalAs(UnmanagedType.SysInt)]IntPtr nSize, [Out, Optional, MarshalAs(UnmanagedType.SysInt)] out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool VirtualProtectEx(HandleRef hProcess, IntPtr lpAddress, [MarshalAs(UnmanagedType.SysInt)] IntPtr dwSize, MemoryProtection flNewProtect, [Out] out MemoryProtection lpflOldProtect);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            public static extern IntPtr VirtualAllocEx(HandleRef hProcess, IntPtr lpAddress, [MarshalAs(UnmanagedType.SysInt)] IntPtr nSize, AllocationOption flAllocationType, MemoryProtection flProtect);

            [DllImport("kernel32.dll", SetLastError = false, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool VirtualFreeEx(HandleRef hProcess, IntPtr lpAddress, [MarshalAs(UnmanagedType.SysInt)] IntPtr nSize, FreeOption dwFreeType);

            [System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Portability", "CA1901:PInvokeDeclarationsShouldBePortable", MessageId = "return")]
            [DllImport("kernel32.dll", SetLastError = false, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool VirtualQueryEx(HandleRef hProcess, IntPtr lpAddress, [In] MemoryBasicInfo lpBuffer, IntPtr dwLength);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            public unsafe static extern SafeWaitHandle CreateRemoteThread(HandleRef hProcess, IntPtr lpThreadAttributes, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, ThreadCreationFlags dwCreationFlags, out int threadID);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool TerminateThread(SafeWaitHandle hThread, int dwExitCode);

            [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
            public static extern WaitObjectResult WaitForSingleObject([In] SafeWaitHandle hHandle, [In] int dwMilliseconds);

            [DllImport("kernel32.dll", SetLastError = false, CallingConvention = CallingConvention.Winapi)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool IsWow64Process(HandleRef hProcess, [Out] out bool Wow64Process);

            [DllImport("kernel32", SetLastError = true)]
            public static extern void GetSystemInfo(SysInfo lpSystemInfo);

            public const int ERROR_NOACCESS = 0x3E6;


            /// <summary>
            /// <para>Process access rights.</para>   
            /// </summary>
            [Flags]
            internal enum ProcessAccessOption : uint
            {
                All = 0x1F0FFF,
                CreateProcess = 0x80,
                CreateThread = 0x02,
                DuplicateHandle = 0x40,
                QueryInformation = 0x400,
                QueryLimitedInformation = 0x1000,
                SetInformation = 0x200,
                SetQuota = 0x100,
                SuspendResume = 0x800,
                Terminate = 0x01,
                VirtualMemoryOperation = 0x08,
                VirtualMemoryRead = 0x10,
                VirtualMemoryWrite = 0x20,
                Synchronize = 0x100000
            }


            /// <summary>
            /// Contains information about a range of pages in the virtual address space of a process. 
            /// </summary>
            [StructLayout(LayoutKind.Sequential)]
            public class MemoryBasicInfo
            {
                /// <summary>
                /// The base address of the region of pages.
                /// </summary>
                public readonly IntPtr BaseAddress;

                /// <summary>
                /// The base address of a range of pages.
                /// </summary>
                public readonly IntPtr AllocationBase;

                private readonly IntPtr _Arg1;
                /// <summary>
                /// The memory protection option when the region was initially allocated. 
                /// </summary>
                public MemoryProtection AllocationProtect => IntPtr.Size == 4 ? (MemoryProtection)_Arg1.ToInt32() : (MemoryProtection)((uint)_Arg1.ToInt32() >> 32);

                /// <summary>
                /// The size of the region beginning at the base address in which all pages have identical attributes, in bytes.
                /// </summary>
                [MarshalAs(UnmanagedType.SysInt)]
                public readonly IntPtr RegionSize;

                /// <summary>
                /// The state of the pages in the region. 
                /// </summary>
                public readonly MemoryState State;

                /// <summary>
                /// The access protection of the pages in the region.
                /// </summary>
                public readonly MemoryProtection Protect;


                private readonly IntPtr _Arg2;

                /// <summary>
                /// The type of pages in the region. The following types are defined.
                /// </summary>
                public MemoryType Type => IntPtr.Size == 4 ? (MemoryType)_Arg1.ToInt32() : (MemoryType)((ulong)_Arg1.ToInt64() >> 4);

                public static readonly IntPtr Size = new IntPtr(Marshal.SizeOf<MemoryBasicInfo>());

            }


            /// <summary>
            /// The state of the pages in the region. 
            /// </summary>
            internal enum MemoryState : uint
            {
                /// <summary>
                /// Indicates committed pages for which physical storage has been allocated, either in memory or in the paging file on disk.
                /// </summary>
                Commit = 0x1000,
                /// <summary>
                /// Indicates free pages not accessible to the calling process and available to be allocated. 
                /// </summary>
                Free = 0x10000,
                /// <summary>
                /// Releases the specified region of pages. 
                /// </summary>
                Reserve = 0x2000
            }

            [Flags]
            public enum MemoryProtection : uint
            {
                /// <summary>
                /// Enables execute access to the committed region of pages. 
                /// </summary>
                Execute = 0x10,
                /// <summary>
                /// Enables execute or read-only access to the committed region of pages. 
                /// </summary>
                ExecuteRead = 0x20,
                /// <summary>
                /// Enables execute, read-only, or read/write access to the committed region of pages.
                /// </summary>
                ExecuteReadWrite = 0x40,
                /// <summary>
                /// Enables execute, read-only, or copy-on-write access to a mapped view of a file mapping object.
                /// </summary>
                ExecuteWriteCopy = 0x80,
                /// <summary>
                /// <para>Disables all access to the committed region of pages.</para>
                /// <para>An attempt to read from, write to, or execute the committed region results in an access violation.</para>
                /// </summary>
                NoAccess = 0x01,
                /// <summary>
                /// Enables read-only access to the committed region of pages. 
                /// </summary>
                ReadOnly = 0x02,
                /// <summary>
                /// Enables read-only or read/write access to the committed region of pages.
                /// </summary>
                ReadWrite = 0x04,
                /// <summary>
                /// Enables read-only or copy-on-write access to a mapped view of a file mapping object. 
                /// </summary>
                WriteCopy = 0x08,
                /// <summary>
                /// Pages in the region become guard pages. 
                /// </summary>
                Guard = 0x100,
                /// <summary>
                /// Sets all pages to be non-cachable. 
                /// </summary>
                NoCache = 0x200,
                /// <summary>
                /// Sets all pages to be write-combined.
                /// </summary>
                WriteCombine = 0x400
            }

            /// <summary>
            /// The type of free operation.
            /// </summary>
            public enum FreeOption
            {
                /// <summary>
                /// Decommits the specified region of committed pages.
                /// </summary>
                Decommit = 0x4000,
                /// <summary>
                /// Releases the specified region of pages. 
                /// </summary>
                Release = 0x8000,
            }

            /// <summary>
            /// <para>The type of memory allocation.</para>
            /// </summary>
            [Flags]
            public enum AllocationOption : uint
            {
                /// <summary>
                /// Allocates memory charges (from the overall size of memory and the paging files on disk) for the specified reserved memory pages.
                /// </summary>
                Commit = 0x1000,
                /// <summary>
                /// Reserves a range of the process's virtual address space without allocating any actual physical storage in memory or in the paging file on disk.
                /// </summary>
                Reserve = 0x2000,
                /// <summary>
                /// Indicates that data in the memory range specified by lpAddress and nSize is no longer of interest.
                /// </summary>
                Reset = 0x80000,
                /// <summary>
                ///<para><see cref="AllocationOption.ResetUndo"/> should only be called on an address range to which <see cref="AllocationOption.Reset"/> was successfully applied earlier.</para> 
                /// <para>It indicates that the data in the specified memory range specified by lpAddress and nSize is of interest to the caller and attempts to reverse the effects of <see cref="AllocationOption.Reset"/>.</para>
                /// </summary>
                ResetUndo = 0x1000000,
                /// <summary>
                /// Allocates memory using large page support.
                /// </summary>
                LargePages = 0x20000000,
                /// <summary>
                /// Reserves an address range that can be used to map Address Windowing Extensions (AWE) pages.
                /// </summary>        
                Physical = 0x400000,
                /// <summary>
                /// Allocates memory at the highest possible address. 
                /// </summary>
                TopDown = 0x100000,

            }

            /// <summary>
            /// <para>Process access rights.</para>   
            /// </summary>
            [Flags]
            public enum ProcessAccess
            {
                All = 0x1F0FFF,
                CreateProcess = 0x80,
                CreateThread = 0x02,
                DuplicateHandle = 0x40,
                QueryInformation = 0x400,
                QueryLimitedInformation = 0x1000,
                SetInformation = 0x200,
                SetQuota = 0x100,
                SuspendResume = 0x800,
                Terminate = 0x01,
                VirtualMemoryOperation = 0x08,
                VirtualMemoryRead = 0x10,
                VirtualMemoryWrite = 0x20,
                Synchronize = 0x100000
            }

            /// <summary>
            /// The type of pages in the region. 
            /// </summary>
            public enum MemoryType : uint
            {
                /// <summary>
                /// Indicates that the memory pages within the region are mapped into the view of an image section.
                /// </summary>
                Image = 0x1000000,
                /// <summary>
                /// Indicates that the memory pages within the region are mapped into the view of a section.
                /// </summary>
                Mapped = 0x40000,
                /// <summary>
                /// Indicates that the memory pages within the region are private (that is, not shared by other processes). 
                /// </summary>
                Private = 0x20000
            }


            public enum ModuleFilter
            {
                LIST_MODULES_DEFAULT = 0x00,
                LIST_MODULES_32BIT = 0x01,
                LIST_MODULES_64BIT = 0x02,
                LIST_MODULES_ALL = 0x03
            }

            [Flags]
            public enum ThreadCreationFlags
            {
                None = 0,
                CREATE_SUSPENDED = 0x00000004,
                STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
            }

            public enum WaitObjectResult : uint
            {
                WAIT_OBJECT_0 = 0x00000000,
                WAIT_TIMEOUT = 0x00000102,
                WAIT_FAILED = 0xFFFFFFFF
            }

            [StructLayout(LayoutKind.Sequential, Pack = 2)]
            public sealed class SysInfo
            {
                private readonly uint OemId;
                public ProcessorArchitecture ProcessorType => (ProcessorArchitecture)(OemId >> 16);
                public ushort Reserved => (ushort)(OemId & 0xFFFF);

                public readonly int PageSize;

                public readonly IntPtr MinimumApplicationAddress;

                public readonly IntPtr MaximumApplicationAddress;

                public readonly IntPtr ActiveProcessorMask;

                public readonly int NumberOfProcessors;

                public readonly ProcessorType OrgProcessorType;

                public readonly int AllocationGranularity;

                public readonly short ProcessorLevel;

                public readonly short ProcessorRevision;
            }

            public enum ProcessorArchitecture : ushort
            {
                PROCESSOR_ARCHITECTURE_AMD64 = 9,
                PROCESSOR_ARCHITECTURE_ARM = 5,
                PROCESSOR_ARCHITECTURE_ARM64 = 12,
                PROCESSOR_ARCHITECTURE_IA64 = 6,
                PROCESSOR_ARCHITECTURE_INTEL = 0,
                PROCESSOR_ARCHITECTURE_UNKNOWN = 0xFFFF
            }

            public enum ProcessorType : uint
            {
                PROCESSOR_INTEL_386 = 386,
                PROCESSOR_INTEL_486 = 486,
                PROCESSOR_INTEL_PENTIUM = 586,
                PROCESSOR_INTEL_IA64 = 2200,
                PROCESSOR_AMD_X8664 = 8664,
            }

        }
    }

}

