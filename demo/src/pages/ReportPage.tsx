import { Link, useParams } from 'react-router-dom';
import { DecisionReportView } from '../components/DecisionReportView';
import { useDemoPlayback } from '../hooks/useDemoPlayback';

export function ReportPage() {
  const { id } = useParams();
  const { session, isLoading } = useDemoPlayback('guide', true, id);

  if (isLoading) {
    return (
      <div className="session-loading">
        <strong>加载报告…</strong>
      </div>
    );
  }

  return (
    <div className="report-page">
      <header className="report-page__header">
        <Link to={`/demo/session/${id}`}>← 返回作战室</Link>
        <Link to="/demo/entry">重新开始</Link>
        <button type="button" onClick={() => window.print()}>打印报告</button>
      </header>
      <DecisionReportView report={session.report} session={session} />
    </div>
  );
}
