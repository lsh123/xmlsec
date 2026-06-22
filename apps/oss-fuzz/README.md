Usually, software teams do functional testing (which is great) but not security testing of their code. For example:

```
func_add(int x, int y) { return x+y; }
```
may have a unit test like so:

```
ASSERT((func_add(4,5)==9))
```
However, corner cases are usually not tested so that `x=INT_MAX; y=1` shows a problem in the implementation/desired output.

Fuzz testing is routinely used to generate such corner cases and feed them to program APIs. oss-fuzz is one such fuzz testing framework that is fully automated and targeted at open-source software (oss) and supported by Google. An enrolled project is continually fuzzed and bug reports are sent to maintainers as and when they are generated.

To enrol a new project into oss-fuzz, the codebase must contain test harnesses that make use of the libFuzzer API. This folder hosts oss-fuzz test harnesses for xmlsec that are picked up by oss-fuzz and built. The build script resides in the oss-fuzz repo under the `projects/xmlsec` folder.
