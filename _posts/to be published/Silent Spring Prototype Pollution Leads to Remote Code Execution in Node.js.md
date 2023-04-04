[toc]

原型污染是影响基于原型的语言（如 JavaScript 和 Node.js）的危险漏洞。它指的是攻击者能够在运行时将属性注入对象的根原型，然后触发由合法代码构造的 Gadgets 的执行，从而导致诸如 DoS、权限提升和远程代码执行等攻击。虽然目前有例子表明原型污染会导致 RCE，但目前的研究并未解决 Gadgets 检测的挑战，因此仅显示了针对 Node.js 库的 DoS 攻击的可行性。

在本文中，我们开始以一种整体的方式研究这个问题，从检测原型污染到检测 Gadgets，目标是在成熟的 Node.js 应用程序中发现 DoS 之外的端到端漏洞。我们构建了第一个多阶段框架，该框架使用多标签静态污点分析来识别 Node.js 库和应用程序中的原型污染，以及检测通用 Gadgets 的混合方法，特别是通过分析 Node.js 源代码。我们在 GitHub 的静态分析框架 CodeQL 之上实现了我们的框架，以在核心 Node.js API 中找到 11 个通用 Gadgets，从而实现代码执行。此外，我们在对 15 个流行的 Node.js 应用程序的研究中使用我们的方法来识别原型污染和小工具。我们在两个备受瞩目的应用程序中手动利用 RCE。我们的结果提供了令人震惊的证据，证明原型污染与强大的通用 Gadgets 相结合会导致 Node.js 中的 RCE。

## ## 1 Introduction

近年来，我们看到人们对在浏览器之外运行 JavaScript 越来越感兴趣。 一个典型的例子是 Node.js，它是一种流行的服务器端运行时，可以创建全栈 Web 应用程序。 它的包管理系统 npm 是世界上最大的软件存储库，拥有数百万个包。 研究人员对这个生态系统进行了广泛的研究，发现了几个安全风险。

原型污染是一个 JavaScript 驱动的漏洞，它在 Node.js 生态系统中表现得很明显。该漏洞植根于语言的许可性质，它允许在全局范围内更改重要的内置对象 - `Object.prototype` - 称为根原型。 JavaScript 基于原型的继承允许通过原型链访问这个重要的对象。因此，攻击者可以通过提供精心设计的属性名称来指示易受攻击的代码改变根原型，以便在运行时访问。结果，从根原型继承的每个对象，即运行时中的绝大多数对象，都继承了根原型上的突变，例如，攻击者控制的属性。这个漏洞最早是由 Arteau 引入的，表明它是 Node.js 库中普遍存在的问题。最近，Li 等人提出了一种静态分析技术，用于使用对象属性图检测原型污染漏洞。

## ## Universal Gadgets

下表概述了目标 Node.js 版本的所有 Gadgets。 一些 Gadgets 是特定于操作系统的，而其中大多数都可以在 Windows 和 Linux 操作系统上运行。我们强调所涉及的各种通用属性，表明 Gadgets 不是孤立的案例，而是常见的地方。这些小工具对应于 Node.js 核心中的少数目标 API，但有动机的攻击者可能会在目标应用程序的代码库中找到更多。最后，正如我们在下面讨论的，一些小工具允许以相对强的前提条件执行任意代码，而另一些小工具允许以较弱的前提条件劫持控制流。更重要的是，攻击者可以结合两个这样的 Gadgets 来获得两全其美的效果。

![image-20220925221213938](C:\Users\whoami\AppData\Roaming\Typora\typora-user-images\image-20220925221213938.png)

我们现在讨论一些最重要的 Gadgets 和要执行的假设。让我们考虑一个使用字符串调用 execSync API 的应用程序：

```js
const { execSync } = require('child_process');
console.log(execSync('echo "hi"').toString());
```

这个看起来不错的代码在控制台中打印字符串 hi。 Staicu 等人的报告说，此类 API 调用在 npm 生态系统中很普遍，但他们认为所有以常量作为参数的调用站点都是安全的，就像上面的那个。这是因为他们假设攻击者无法操纵命令的值，因为它被开发人员设置为固定值。我们发现这种假设在存在原型污染的情况下不成立。如果攻击者可以在运行时污染任意属性，他们就可以劫持要执行的命令及其环境变量。考虑污染的属性：

```js
Object.prototype.shell = "node";
Object.prototype.env = {};
Object.prototype.env.NODE_OPTIONS = "--inspect-brk=0.0.0.0:1337 ";
```

他们欺骗上面的合法代码在调试端口打开的情况下生成一个新的 Node.js 进程，充当反向 Shell。这是因为被污染的属性 `shell` 覆盖了开发人员给出的命令，并且 `env.NODE_OPTIONS` 被设置为当前进程的环境变量，随后复制到所有子进程。

所展示的 Gadgets 会影响 Node.js 中用于命令执行的所有 API：spawn、spawnSync、exec、execSync、execFileSync。这种攻击的先决条件是目标命令执行调用站点不应显式设置选项参数，例如，对于 execSync 调用，不应传递第二个参数。这个 Gadgets 的存在意味着每个容易受到原型污染并在污染后使用命令执行 API 的 Node.js 应用程序都容易受到远程代码执行的影响。

现在考虑一个不直接在面向用户的代码中使用此类 API 的应用程序。攻击者仍然可以利用机器上存在的代码来触发命令执行 API。我们发现了三个利用 `require` 和 `import` 方法的小工具。考虑以下示例：

```js
Object.prototype.main = "./../../pwned.js"
// trigger call
require('my-package')
```

此 Gadgets 的前提条件是 my-package 在其 package.json 中没有定义 `main` 属性。如果根原型的 `main` 属性被污染，则在 `require` 时，该属性的值用于检索要执行的代码，而不是模块的合法代码。因此，攻击者可以指示要在引擎中加载的磁盘上的任意文件。特别是，他们可以指定一个包含对命令执行 API 的调用的文件。例如，流行的 [growl](https://
www.npmjs.com/package/growl) 包中包含一个名为 test.js 的文件，该文件调用具有不同测试值的包。考虑到 growl 在内部使用 spawn，攻击者可以通过将 main 属性设置为指向 growl 的 test.js 文件来成功触发此类 API 调用。此外，我们还发现了 npm 命令行工具附带的一个文件，该文件可用于相同的恶意目的：`npm/scripts/changelog.js`。

据我们所知，上面的 Gadget 是报告的第一个表明在 Node.js 中通过代码重用攻击劫持控制流是可能的证据。这激发了对像 Mininode 这样的去膨胀技术的需求。除了已经令人震惊的发现之外，攻击者还可以结合上面讨论的两个 Gadgets 来获得一个强大的通用 Gadget：

```js
// pollutions for the first gadget
Object.prototype.main = "/path/to/npm/scripts/changelog.js";
// pollutions for the second gadget
Object.prototype.shell = "node";
Object.prototype.env = {};
Object.prototype.env.NODE_OPTIONS = "--inspect-brk=0.0.0.0:1337";
// trigger call
require("bytes");
```

加载 bytes 包时，第一个 Gadget 会指示引擎加载 changelog.js 文件。该文件依次调用 execSync，它触发第二个 Gadget，启动带有调试会话的 Node.js 进程。

最后，让我们展示另一个可以让攻击者将任意文件加载到引擎中的 Gadget。通过污染根原型的属性 `1` 和 `exports`，攻击者可以在从磁盘加载相对路径时执行任意文件：

```js
let rootProto = Object.prototype;
rootProto["exports"] = {".":"./changelog.js"};
rootProto["1"] = "/path/to/npm/scripts/";
// trigger call
require("./target.js");
```

在执行相对路径解析时，`require` 方法会检查目标路径是否指向 ES6 模块。在此过程中，在文件 `/internal/modules/cjs/loader.js` 中应用解构运算符时，无意中读取了污染属性 `1`：

```js
const { 1: name , 2: expansion = "" } = StringPrototypeMatch (...) || [];
```

因此，攻击者控制的值被分配为目标模块的名称。此后，`require` 方法错误地断定相对路径 `./target.js` 解析为攻击者控制的位置 `/path/to/npm/scripts/` 并且该路径对应于 ES6 模块。通过为这个不存在的模块提供入口点，`exports` 属性用于进一步混淆 `require` 方法。尽管在攻击者控制的目标位置不存在 package.json 文件，但 `require` 方法仍然成功返回，这是一个有效的模块路径。我们注意到这个 Gadget 不能移植到旧的 Node.js 版本，例如版本 14.15.0。 因此，利用的一个重要前提是目标系统必须使用最新的 Node.js 版本。

我们再次强调已识别的 Gadgets 有多么危险。一旦原型污染到位，许多相当大的应用程序可能会满足 RCE 的先决条件

1. 需要使用相对路径的文件或没有 `main` 条目的包。
2. 具有依赖关系，加载时使用命令执行 API。

为了进一步研究我们的 Gadgets 的影响，我们在对 10,000 个最依赖 npm 包的实验中估计了它们的触发器的普遍性。我们测得 1,958 个在他们的 package.json 中没有 `main` 条目（G4、G5、G10），4,420 个在 `require` 语句中使用相对路径（G6、G8、G11），而 355 个直接使用命令注入 API（G1、G2、G3 ）。这表明，一旦污染到位，我们的许多 Gadgets 都可以针对这些软件包的客户端部署。





































































































































































































