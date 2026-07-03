import { Navigate, Route, Routes } from 'react-router-dom';
import { ComparePage } from './pages/ComparePage';
import { EntryPage } from './pages/EntryPage';
import { ReportPage } from './pages/ReportPage';
import { SessionPage } from './pages/SessionPage';
import './App.css';

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/demo/entry" replace />} />
      <Route path="/demo/entry" element={<EntryPage />} />
      <Route path="/demo/session/:id" element={<SessionPage />} />
      <Route path="/demo/session/:id/report" element={<ReportPage />} />
      <Route path="/demo/compare" element={<ComparePage />} />
    </Routes>
  );
}
