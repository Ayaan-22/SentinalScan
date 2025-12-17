import React from "react";

const StatsCard = ({ title, value, icon, color }) => (
  <div className="glass-card p-4 flex items-center gap-4">
    <div
      className={`w-12 h-12 rounded-lg flex items-center justify-center ${color}`}
    >
      {icon}
    </div>
    <div>
      <div className="text-slate-400 text-xs uppercase font-medium tracking-wider">
        {title}
      </div>
      <div className="text-2xl font-bold font-mono mt-1">{value}</div>
    </div>
  </div>
);

export default StatsCard;
