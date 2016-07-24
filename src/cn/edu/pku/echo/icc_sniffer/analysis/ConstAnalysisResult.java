package cn.edu.pku.echo.icc_sniffer.analysis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.insn.ConstStmtNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.FieldStmtNode;
import com.googlecode.d2j.node.insn.MethodStmtNode;
import com.googlecode.d2j.node.insn.Stmt1RNode;
import com.googlecode.d2j.node.insn.Stmt2R1NNode;
import com.googlecode.d2j.node.insn.Stmt2RNode;
import com.googlecode.d2j.node.insn.TypeStmtNode;
import com.googlecode.d2j.reader.Op;

import cn.edu.pku.echo.icc_sniffer.analysis.object.AOComponentName;
import cn.edu.pku.echo.icc_sniffer.analysis.object.AOIntent;
import cn.edu.pku.echo.icc_sniffer.analysis.object.AOString;
import cn.edu.pku.echo.icc_sniffer.analysis.object.AnalysisObject;
import cn.edu.pku.echo.icc_sniffer.main.ConstConfig;

class RegisterList {
	List<AnalysisObject> registers;

	public RegisterList(int registerNum) {
		registers = new ArrayList<AnalysisObject>();
		for (int i = 0; i < registerNum; ++i)
			registers.add(null);
	}

	public RegisterList copy() {
		RegisterList ret = new RegisterList(registers.size());
		for (int i = 0; i < registers.size(); ++i)
			if (registers.get(i) != null)
				ret.registers.set(i, registers.get(i).copy());
		return ret;
	}

	public void printRegisters() {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		for (AnalysisObject ao : registers) {
			if (ao instanceof AOString)
				sb.append("AOString," + ((AOString) ao).str);
			else if (ao instanceof AOIntent) {
				AOIntent intent = (AOIntent) ao;
				sb.append("AOIntent,");
				sb.append(((AOIntent) ao).action + ",");
				sb.append(((AOIntent) ao).categories + ",");
				if (intent.component != null)
					sb.append(intent.component.package_name + "/" + intent.component.activity_name + ",");
				else
					sb.append("/");
			} else if (ao instanceof AOComponentName)
				sb.append("(AOComponentName," + ((AOComponentName) ao).activity_name + "),");
			else
				sb.append("null,");
			sb.append("|");
		}
		sb.append("}");
		System.out.println(sb);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		RegisterList other = (RegisterList) obj;
		if (this.registers.size() != other.registers.size())
			return false;
		for (int i = 0; i < this.registers.size(); ++i) {
			if (this.registers.get(i) != null && !(this.registers.get(i).equals(other.registers.get(i))))
				return false;
		}
		return true;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		for (AnalysisObject ao : registers) {
			result = prime * result + ((ao == null) ? 0 : ao.hashCode());
		}
		return result;
	}
}

public class ConstAnalysisResult extends AnalysisResult {

	public Set<RegisterList> values;
	public Map<Method, AnalysisResult> const_args_map;

	public ConstAnalysisResult(int totalRegisters) {
		values = new HashSet<RegisterList>();
		values.add(new RegisterList(totalRegisters));
	}

	public ConstAnalysisResult(ConstAnalysisResult other) {
		values = new HashSet<RegisterList>();
		for (RegisterList rl : other.values)
			values.add(rl.copy());
	}

	public void initParams(AnalysisResult params) {
		ConstAnalysisResult res = (ConstAnalysisResult) params;
		Set<RegisterList> new_values = new HashSet<RegisterList>();
		for (RegisterList rl : this.values) {
			for (RegisterList param_rl : res.values) {
				RegisterList new_rl = rl.copy();
				for (int i = 0; i < param_rl.registers.size(); ++i) {
					int index1 = new_rl.registers.size() - i - 1;
					int index2 = param_rl.registers.size() - i - 1;
					AnalysisObject ao = param_rl.registers.get(index2);
					if (ao != null)
						new_rl.registers.set(index1, ao.copy());
					else
						new_rl.registers.set(index1, null);
				}
				new_values.add(new_rl);
			}
		}
		this.values = new_values;
	}

	private void addConstMethodMap(MethodStmtNode msn, RegisterList rl, int[] args) {
		int para_len = args.length;
		Method method = msn.method;
		boolean isStatic = (msn.op.equals(Op.INVOKE_STATIC) || msn.op.equals(Op.INVOKE_STATIC_RANGE));
		int offset = isStatic ? 0 : 1;
		if (const_args_map.get(method) == null)
			const_args_map.put(method, new ConstAnalysisResult(para_len - offset));
		RegisterList new_rl = new RegisterList(para_len - offset);
		for (int i = offset; i < para_len; ++i) {
			new_rl.registers.set(i - offset, rl.registers.get(args[i]));
		}
		ConstAnalysisResult results = (ConstAnalysisResult) const_args_map.get(method);
		results.values.add(new_rl);
	}

	@Override
	public void merge(DexStmtNode insn) {
		// System.out.println("merge statement " + this.hashCode());
		if (insn instanceof ConstStmtNode) {
			ConstStmtNode csn = (ConstStmtNode) insn;
			if (ConstMethods.isNewInstanceString(insn)) {
				for (RegisterList rl : values) {
					String str = (String) csn.value;
					if (ConstConfig.interested_string.matcher(str).matches())
						rl.registers.set(csn.a, new AOString(str));
				}
			} else {
				for (RegisterList rl : values) {
					rl.registers.set(csn.a, null);
				}
			}
		} else if (insn instanceof Stmt2RNode) {
			Stmt2RNode s2rn = (Stmt2RNode) insn;
			if (insn.op.opcode >= 0x01 && insn.op.opcode <= 0x09) {
				for (RegisterList rl : values) {
					rl.registers.set(s2rn.a, rl.registers.get(s2rn.b));
				}
			}
		} else if (insn instanceof Stmt1RNode) {
			Stmt1RNode s1rn = (Stmt1RNode) insn;
			if (insn.op.equals(Op.MOVE_RESULT) || insn.op.equals(Op.MOVE_RESULT_OBJECT)
					|| insn.op.equals(Op.MOVE_RESULT_WIDE)) {
				for (RegisterList rl : values) {
					rl.registers.set(s1rn.a, null);
				}
			}
		} else if (insn instanceof FieldStmtNode) {
			FieldStmtNode fsn = (FieldStmtNode) insn;
			if ((insn.op.opcode >= 0x52 && insn.op.opcode <= 0x58) // IGET
					|| (insn.op.opcode >= 0x60 && insn.op.opcode <= 0x66)) { // SGET
				for (RegisterList rl : values) {
					rl.registers.set(fsn.a, null);
				}
			}
		} else if (insn instanceof TypeStmtNode) {
			TypeStmtNode tsn = (TypeStmtNode) insn;
			if (ConstMethods.isNewInstanceComponentName(insn)) {
				for (RegisterList rl : values) {
					rl.registers.set(tsn.a, new AOComponentName());
				}
			} else if (ConstMethods.isNewInstanceIntent(insn)) {
				for (RegisterList rl : values) {
					rl.registers.set(tsn.a, new AOIntent());
				}
			} else {
				for (RegisterList rl : values) {
					rl.registers.set(tsn.a, null);
				}
			}

		} else if (insn instanceof MethodStmtNode) {
			MethodStmtNode msn = (MethodStmtNode) insn;
			if (ConstMethods.isInitComponentName(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOComponentName)) {
						rl.registers.set(msn.args[0], new AOComponentName());
						ao = rl.registers.get(msn.args[0]);
					}
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					AnalysisObject ao2 = rl.registers.get(msn.args[2]);
					((AOComponentName) ao).package_name = (ao1 instanceof AOString) ? ((AOString) ao1).str : null;
					((AOComponentName) ao).activity_name = (ao2 instanceof AOString) ? ((AOString) ao2).str : null;
				}
			} else if (ConstMethods.isInitIntent(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					if (msn.args.length > 1) {
						AnalysisObject ao1 = rl.registers.get(msn.args[1]);
						if (!(ao1 instanceof AOString)) {
							// System.out.println("params not string in
							// isInitIntent");
							continue;
						}
						((AOIntent) ao).action = ((AOString) ao1).str;
					}
				}
			}
			if (ConstMethods.isSetAction(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					if (!(ao1 instanceof AOString)) {
						// System.out.println("params not string in
						// isSetAction");
						continue;
					}
					((AOIntent) ao).action = ((AOString) ao1).str;
				}
			} else if (ConstMethods.isSetComponent(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					if (!(ao1 instanceof AOComponentName)) {
						// System.out.println("params not string in
						// isSetComponent");
						continue;
					}
					((AOIntent) ao).component = (AOComponentName) ((AOComponentName) ao1).copy();
				}
			} else if (ConstMethods.isSetClassName(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					String s1 = "";
					String s2 = "";
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					if (ao1 instanceof AOString) {
						s1 = ((AOString) ao1).str;
					}
					AnalysisObject ao2 = rl.registers.get(msn.args[2]);
					if (ao2 instanceof AOString) {
						s2 = ((AOString) ao2).str;
					}
					((AOIntent) ao).component = new AOComponentName(s1, s2);
				}
			} else if (ConstMethods.isSetPackage(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					String s1 = "";
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					if (ao1 instanceof AOString) {
						s1 = ((AOString) ao1).str;
					}
					AOIntent intent = (AOIntent) ao;
					if (intent.component == null)
						intent.component = new AOComponentName(s1, "");
					else
						intent.component.package_name = s1;
				}
			} else if (ConstMethods.isAddCategory(insn)) {
				for (RegisterList rl : values) {
					AnalysisObject ao = rl.registers.get(msn.args[0]);
					if (!(ao instanceof AOIntent)) {
						rl.registers.set(msn.args[0], new AOIntent());
						ao = rl.registers.get(msn.args[0]);
					}
					String s1 = "";
					AnalysisObject ao1 = rl.registers.get(msn.args[1]);
					if (ao1 instanceof AOString) {
						s1 = ((AOString) ao1).str;
					}
					((AOIntent) ao).categories = ((AOIntent) ao).categories + s1 + ";";
				}
			}
		}

		if (insn instanceof MethodStmtNode) {
			MethodStmtNode msn = (MethodStmtNode) insn;

			int[] args = msn.args;
			for (RegisterList rl : values) {
				boolean live = false;
				for (int i = 0; i < args.length; ++i) {
					if (rl.registers.get(args[i]) != null) {
						live = true;
						break;
					}
				}
				if (live) {
					addConstMethodMap(msn, rl, args);
				}
			}
		}
	}

	@Override
	public void printResult() {
		for (RegisterList rl : values) {
			rl.printRegisters();
		}
		System.out.println("");
	}

	@Override
	public boolean covers(AnalysisResult result) {
		// System.out.println("covers");
		ConstAnalysisResult res = (ConstAnalysisResult) result;
		if (this.values.size() < res.values.size())
			return false;
		for (RegisterList rl : res.values) {
			if (!this.values.contains(rl))
				return false;
		}
		return true;
	}

	@Override
	public void mergeResult(AnalysisResult result) {
		// System.out.println("merge result");
		ConstAnalysisResult res = (ConstAnalysisResult) result;
		for (RegisterList rl : res.values) {
			if (!this.values.contains(rl))
				this.values.add(rl.copy());
		}
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		ConstAnalysisResult other = (ConstAnalysisResult) obj;
		if (this.values.size() != other.values.size())
			return false;
		for (RegisterList rl : this.values) {
			if (!other.values.contains(rl))
				return false;
		}
		return true;
	}

	@Override
	public AnalysisResult clone() {
		return new ConstAnalysisResult(this);
	}
}