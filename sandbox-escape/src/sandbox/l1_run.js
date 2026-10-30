// =============================================================================
//  L1 执行器：把用户代码丢进 Node 的 vm 模块里跑
// =============================================================================
//  vm.createContext() 造出来的「干净上下文」里没有 process、没有 require、
//  没有 Buffer —— 看起来像个沙箱，但 Node 官方文档写得很直白：
//
//      "The vm module is not a security mechanism.
//       Do not use it to run untrusted code."
//
//  原因：沙箱里的对象本质上还是**宿主 realm 的对象**。只要拿到任意一个对象，
//  就能顺着 constructor 链摸到宿主 realm 的 Function 构造函数，
//  用它 new 出来的函数是宿主作用域里的函数，作用域链最顶端就是 global。
//
//  这一关要你自己找到那条链。
// =============================================================================

const vm = require('vm');
const fs = require('fs');
const util = require('util');

let code = '';
try {
  code = fs.readFileSync(0, 'utf8');   // 从 stdin 读用户代码
} catch (e) {
  console.error('[sandbox] 读不到输入');
  process.exit(0);
}

// 沙箱里只给一个 print —— 相当于真实产品里那种「计算器 / 表达式求值」接口
const sandbox = {
  print: (v) => process.stdout.write(String(v) + '\n'),
};

const ctx = vm.createContext(sandbox, { name: 'sandbox' });

try {
  // timeout 只挡得住同步死循环，挡不住逃逸 —— 逃出去之后是宿主进程在跑
  const result = vm.runInContext(code, ctx, { timeout: 1000, displayErrors: true });
  if (result !== undefined) {
    process.stdout.write('[sandbox] ' + util.inspect(result) + '\n');
  }
} catch (e) {
  const name = e && e.name ? e.name : 'Error';
  const msg = e && e.message ? e.message : String(e);
  console.error('[sandbox] ' + name + ': ' + msg);
}
