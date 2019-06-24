# ProcessPlugin
A .NET Framework project for the System.Diagnostics.Process class enhancement. 

This repo only have a single file，hence there is no need to release any boring binary file with your project.

## Requirements
* Windows Vista or later;
* Intel CPU;
* C# 7.3
* .NET Frameworks 4.5;

## Build Options
* Choose 'Any CPU' platform;
* Enable 'Allow unsafe code';
* Disable 'Prefer 32 bit'

## Features

`using System.Diagnostics.ProcessExtensions;`

### Process Main Window

```
System.Diagnostics.Process proc = ProcessPlugin.GetProcessByWindow("main window title");

var plugin = new ProcessPlugin(proc);

//Main window class name
string wcn = plugin.MainWindowClassName;
```
### Process Memory

```
byte result = plugin.ReadData<byte>(IntPtr.Zero);

plugin.WriteData<byte>(IntPtr.Zero, 0, 1, 2, 3);

//returns the address of specified bytes in process memory.
IntPtr codeAddress = plugin.ScanBytes(new byte[] { 1, 2, 3 });

// allocated 1kb memory.
IntPtr address1 = plugin.AllocatedMemories.Allocate(1024);

// allocated 2kb memory, whose address is near the 'IntPtr.Zero'.
IntPtr address2 = plugin.AllocatedMemories.Allocate(IntPtr.Zero,2048);

plugin.AllocatedMemories.Free(address1);
            
//free address2.
plugin.AllocatedMemories.FreeAt(0);
```
### Process module

```
 //Both 32 bit and 64 bit module can be found.
 ProcessModuleAlter module = plugin.GetModuleByName("module name");

 var xxHash32 = module.GetHashCode();
```


### Remote Calling

` plugin.CallRemoteFunction(IntPtr.Zero);`

### Advanced Features

```
plugin.Advanced.Enabled = true;

IntPtr func = plugin.Advanced.GetFunctionAddress("kernel32", "LoadLibraryA");

//if it's mono 
if (plugin.Advanced.MonoSupported)
{
    var asm = plugin.Advanced.GetAssemblyCSharp();

    //Static fields start address.
    IntPtr sfAddress = plugin.Advanced.GetStaticFields(asm, "namespace", "class");

    IntPtr mAddress = plugin.Advanced.GetMethodAddress(asm, "namespace", "class", "method name");

    IntPtr pgAddress = plugin.Advanced.GetPropertyGetterAddress(asm, "namespace", "class", "property name");

    IntPtr psAddress = plugin.Advanced.GetPropertySetterAddress(asm, "namespace", "class", "property name");
}
```
