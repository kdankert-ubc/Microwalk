# Microwalk

<img align="right" width="100px" height="100px" src="resources/logo/microwalk.svg">

Microwalk is a microarchitectural leakage detection framework, which combines dynamic instrumentation and statistical methods in order to localize and quantify side-channel leakages.

If you are not yet familiar with side-channel attacks and Microwalk's analysis approach, read our quick [introduction](docs/introduction.md).

## Usage

A tutorial showing the necessary steps for running Microwalk locally is in [docs/usage.md](docs/usage.md).

In addition, we offer a number of simple [templates](templates/) for generic analysis tasks, which serve as configuration examples and can be adapted for your specific workload. This also includes templates for running Microwalk within a continuous integration pipeline (CI) like GitHub Actions (feel free to also checkout the [example-c](https://github.com/microwalk-project/example-c) and [example-js](https://github.com/microwalk-project/example-js) repositories for a demo of Microwalk's GitHub integration).

<p align="center">
  <img width="500px" src="resources/images/screenshot.png" alt="Microwalk analysis report embedded into the source code, as shown in the GitHub UI">
</p>

Microwalk comes with a set of preconfigured Docker images, which hold all necessary dependencies and configuration, and are used by the various template. Pre-built images are located in [GitHub's container registry](https://github.com/microwalk-project/Microwalk/pkgs/container/microwalk). See [Microwalk Docker Images](docker/README.md) for details.


## Compiling

If you just want to use Microwalk with your project, you don't need to read further -- we recommend using our templates and the pre-built Docker images, as detailed above. The following documentation is for building and running Microwalk directly from source, as is required when working on the Microwalk code and adding new analysis plugins.

For Windows, it is recommended to install Visual Studio, as it brings almost all dependencies and compilers, as well as debugging support. The solution can then be built directly in the IDE.

The following guide is mostly for Linux systems and command line builds on Windows.

### Main application

The main application is based on [.NET 8.0](https://dotnet.microsoft.com/download/dotnet/8.0), so the .NET 8.0 SDK is required for compiling.

Compile (optional):
```
cd Microwalk
dotnet build -c Release
```

Run (compiles and executes; if you compile manually, you can suppress compiliation with `--no-build`):
```
cd Microwalk
dotnet run -c Release <args>
```

The command line arguments `<args>` are documented in Section "[Running Microwalk](#running-microwalk)".

### Pin tool

Microwalk comes with a Pin tool for instrumenting and tracing x86 binaries. Building the Pin tool requires the [full Pin kit](https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html), preferably the latest version. It is assumed that Pin's directory path is contained in the variable `$pinDir`.

**When building through Visual Studio**: Edit [Settings.props](PinTracer/Settings.props) to point to the Pin directory.

Compile:
```
cd PinTracer
make PIN_ROOT="$pinDir" obj-intel64/PinTracer.so
```

Run (assuming the `pin` executable is in the system's `PATH`):
```
pin -t PinTracer/obj-intel64/PinTracer.so -o /path/to/output/file -- /path/to/wrapper/executable
```

Note that the above run command is needed for testing/debugging only, since `Microwalk` calls the Pin tool itself.

### Pin wrapper executable

In order to efficiently generate Pin-based trace data, Microwalk needs a special wrapper executable which interactively loads and executes test cases. The `PinTracerWrapper` project contains a skeleton program with further instructions ("`/*** TODO ***/`").

The wrapper skeleton is C++-compatible and needs to be linked against the target library. It works on both Windows and Linux (GCC).

Alternatively, it is also possible to use an own wrapper implementation, as long as it exports the Pin notification functions and correctly handles `stdin`.

## Running Microwalk

After composing a suitable configuration file (see [documentation](docs/config.md)), you can run Microwalk with the following command line arguments:

- `<configuration file>` (mandatory)<br>
  The path to the configuration file.
  
- `-p <plugin directory>` (optional)<br>
  A directory containing plugin binaries. This needs to be specified when the configuration references a plugin that is not in Microwalk's main build directory. This option can be supplied multiple times.
  

## Creating own framework modules

Follow these steps to create a custom framework plugin with a new module:
1. Create a new project `MyPlugin` and add a reference to the `Microwalk.FrameworkBase` project.

2. Create a class `PluginMain` which derives from `Microwalk.FrameworkBase.PluginBase`. In this class, you need to override the `Register()` function (see step 5).

3. Create a class `MyModule` for your new module, which inherits from `XXXStage` and has a `[FrameworkModule(<name>, <description>)]` attribute. `XXXStage` here corresponds to one of the framework's pipeline stages:
    - `TestcaseStage`: Produces a new testcase on each call.
    - `TraceStage`: Takes a testcases and generates raw trace data.
    - `PreprocessorStage`: Takes raw trace data and preprocesses it.
    - `AnalysisStage`: Takes preprocessed trace data and updates its internal state for each trace. Yields an analysis result once the finish function is called.
    
4. Implement the module logic.

5. Register the module by calling `XXXStage.Factory.Register<MyModule>()` in `PluginMain.Register()`.

6. Compile the plugin project.

7. Run Microwalk and pass the plugin's build folder via the `-p` command line switch.

Look into the `Microwalk.Plugins.PinTracer` project for some examples.

## Papers
- Jan Wichelmann, Ahmad Moghimi, Thomas Eisenbarth, and Berk Sunar. 2018. **Microwalk: A Framework for Finding Side Channels in Binaries**. In Proceedings of the 34th Annual Computer Security Applications Conference (ACSAC '18). Association for Computing Machinery, New York, NY, USA, 161–173. ([DOI](https://doi.org/10.1145/3274694.3274741), [arXiv](https://arxiv.org/abs/1808.05575))
- Jan Wichelmann, Florian Sieck, Anna Pätschke, and Thomas Eisenbarth. 2022. **Microwalk-CI: Practical Side-Channel Analysis for JavaScript Applications**. In Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security (CCS ’22), November 7–11, 2022, Los Angeles, CA, USA. ACM, New York, NY, USA, 16 pages. ([DOI](https://doi.org/10.1145/3548606.3560654), [arXiv](https://arxiv.org/abs/2208.14942))

## Contributing

Contributions are appreciated! Feel free to submit issues and pull requests.

## License

The entire project is licensed under the MIT license. For further information refer to the [LICENSE](LICENSE) file.

The Microwalk logo can be used under the CC-BY-SA license.
