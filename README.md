# pibench

论文《大语言模型提示注入与越狱攻击的纵深防御框架及评估方法》的配套代码与数据，
对应正文 6.3–6.5 节。仅依赖 Python 标准库（3.8+）。

## 运行

```bash
python run_all.py          # 语料生成 + 输入侧检测 + 输出侧管控
python run_all.py --quick  # 只跑 P1 随机 5 折
python plot_results.py     # 读取 results/summary.json 出图
```

## 目录

```
run_all.py                 实验入口
plot_results.py            出图
pibench/
  datasets.py              语料：模板 + 槽位 + 包装器
  preprocess.py            归一化与结构特征
  detectors.py             D1 规则 / D2 朴素贝叶斯 / D3 困惑度 / D4–D6 消融与级联
  metrics.py               指标与交叉验证协议
  gate.py                  输出通道解析与四档关口
  chart.py                 SVG 绘图
data/corpus.jsonl          468 条语料
results/                   detectors.csv / gate.csv / summary.json / fig_*.svg
```

## 说明

语料 468 条：注入 288 条（6 类攻击 × 8 模板 × 6 种包装），良性 180 条（18 条常规 +
12 条硬负例模板，各 × 6 包装）。攻击与良性共用同一组包装器，随机种子见 `datasets.SEED`。

两种协议：P1 随机 5 折，P2 按模板分组 5 折（测试模板未在训练集中出现）。阈值在训练折内部
20% 验证集上按宏平均 F1 选取。

实验为组件级评测，不调用大模型，衡量的是检测器与网关自身的行为。

## 数据声明

语料为合成文本，不含真实用户数据；`evil.example` 等为保留域名。载荷仅用于检测方法评测。
CVE-2025-32711 的分析依据公开漏洞公告与论文，未对任何在线系统进行测试。
