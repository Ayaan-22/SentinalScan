import React from "react";
import { motion } from "framer-motion";

function StatsCard({ title, value, icon, color, bg, border, delay = 0 }) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay }}
      className={`glass-card p-4 md:p-6 relative overflow-hidden group ${
        border ? `border ${border}` : ""
      } ${bg ? bg : ""}`}
    >
      <div className="flex items-start justify-between">
        <div className="z-10">
          <p className="text-sm font-medium text-slate-400 uppercase tracking-widest mb-1">
            {title}
          </p>
          <div className="flex items-baseline gap-2">
            <h3 className="text-3xl font-bold text-white tracking-tight tabular-nums">
              {value}
            </h3>
            {value > 0 && (
              <span className="text-xs font-bold text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded border border-green-500/20">
                +{(value * 0.1).toFixed(0)}%
              </span>
            )}
          </div>
        </div>
        <div
          className={`p-3 rounded-xl ${bg} backdrop-blur-md border border-white/5 shadow-lg group-hover:scale-110 transition-transform duration-300`}
        >
          <div className={color}>{icon}</div>
        </div>
      </div>

      {/* Decorative gradient blob */}
      <div
        className={`absolute -right-6 -bottom-6 w-24 h-24 rounded-full blur-2xl opacity-20 group-hover:opacity-40 transition-opacity duration-300 ${color.replace(
          "text-",
          "bg-"
        )}`}
      ></div>
    </motion.div>
  );
}

export default StatsCard;
