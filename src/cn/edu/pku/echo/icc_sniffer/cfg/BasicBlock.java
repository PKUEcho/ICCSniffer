package cn.edu.pku.echo.icc_sniffer.cfg;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.googlecode.d2j.DexLabel;
import com.googlecode.d2j.Method;
import com.googlecode.d2j.node.insn.BaseSwitchStmtNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.JumpStmtNode;
import com.googlecode.d2j.node.insn.DexLabelStmtNode;
import com.googlecode.d2j.visitors.DexCodeVisitor;

import cn.edu.pku.echo.icc_sniffer.analysis.AnalysisResult;
import cn.edu.pku.echo.icc_sniffer.analysis.ConstAnalysisResult;

public class BasicBlock {
	private int id;
	public List<DexStmtNode> insn;
	public Set<DexLabel> sucLabels;
	public ConstAnalysisResult preResult;
	public ConstAnalysisResult sucResult;

	public BasicBlock(int id, int totalRegister) {
		this.setId(id);
		insn = new ArrayList<DexStmtNode>();
		sucLabels = new HashSet<DexLabel>();
		preResult = new ConstAnalysisResult(totalRegister);
		sucResult = new ConstAnalysisResult(totalRegister);
	}
	
	public boolean execute(Map<Method, AnalysisResult> const_args_map) {
//		System.out.println("execute block id: " + this.id
//				+ " insn number: " + insn.size() + " status: " + sucResult.values.size());
//		if (this.id == 528) {
//			System.out.println("###########PreResult###########");
//			preResult.printResult();
//		}
//		System.out.println("###########SucResult###########");
//		sucResult.printResult();
		ConstAnalysisResult curResult = new ConstAnalysisResult(preResult);
		curResult.const_args_map = const_args_map;
		for (DexStmtNode dsn : insn) {
			curResult.merge(dsn);
		}
		boolean ret = curResult.equals(sucResult);
		sucResult = curResult;
		return ret;
	}

	public void addInsn(DexStmtNode dsn) {
		insn.add(dsn);
	}

	public boolean canContinue() {
		DexStmtNode lastInsn = getLastInsn();
		return lastInsn != null
				&& (lastInsn.op != null && lastInsn.op.canContinue() || lastInsn instanceof DexLabelStmtNode);
	}

	private DexStmtNode getLastInsn() {
		int size = insn.size();
		if (size > 0)
			return insn.get(size - 1);
		else
			return null;
	}

	public boolean canReturn() {
		DexStmtNode lastInsn = getLastInsn();
		return lastInsn != null && lastInsn.op != null
				&& lastInsn.op.canReturn();
	}

	public boolean canThrow() {
		DexStmtNode lastInsn = getLastInsn();
		return lastInsn != null && lastInsn.op != null
				&& lastInsn.op.canThrow();
	}

	public boolean canBranch() {
		DexStmtNode lastInsn = getLastInsn();
		return lastInsn != null && lastInsn.op != null
				&& lastInsn.op.canBranch();
	}

	public boolean canSwitch() {
		DexStmtNode lastInsn = getLastInsn();
		return lastInsn != null && lastInsn.op != null
				&& lastInsn.op.canSwitch();
	}

	public Set<DexLabel> getSucLabels() {
		return sucLabels;
	}

	public void markSucLabel() {
		DexStmtNode lastInsn = getLastInsn();
		if (lastInsn instanceof BaseSwitchStmtNode) {
			BaseSwitchStmtNode switchStmt = (BaseSwitchStmtNode) lastInsn;
			for (DexLabel label : switchStmt.labels)
				sucLabels.add(label);
		}
		if (lastInsn instanceof JumpStmtNode) {
			JumpStmtNode jumpStmt = (JumpStmtNode) lastInsn;
			sucLabels.add(jumpStmt.label);
		}
	}

	/**
	 * @return the id
	 */
	public int getId() {
		return id;
	}

	/**
	 * @param id
	 *            the id to set
	 */
	public void setId(int id) {
		this.id = id;
	}

	public void accept(DexCodeVisitor dcp) {
		for (DexStmtNode dsn : insn) {
			dsn.accept(dcp);
		}
	}
}
