import { useState } from 'react';

const FAQ = [
  { q: '是不是两个环？', a: '不是。一个 while；决策账是第四本账。' },
  { q: '播种是不是编故事？', a: '是廉价先验，会被证据冲刷；价值在累积更新。' },
  { q: 'null 是不是误报？', a: '主力是分支定界；整案 dismiss 很罕见。' },
  { q: 'Beta 和决策账啥关系？', a: 'Beta：挖不挖得到；决策账：挖到了算哪个故事。' },
  { q: '为何定界探针排第一？', a: 'VOI 边界项给「确认不属于本案」正分。' },
];

export function FaqBubble() {
  const [open, setOpen] = useState(false);

  return (
    <div className="faq-bubble">
      <button type="button" className="faq-bubble__trigger" onClick={() => setOpen(!open)}>
        ？
      </button>
      {open && (
        <div className="faq-bubble__panel">
          <h4>常见问题</h4>
          <dl>
            {FAQ.map(({ q, a }) => (
              <div key={q}>
                <dt>{q}</dt>
                <dd>{a}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
