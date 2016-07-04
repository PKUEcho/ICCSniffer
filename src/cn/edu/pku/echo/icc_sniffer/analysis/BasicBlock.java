package cn.edu.pku.echo.icc_sniffer.analysis;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import com.googlecode.d2j.DexLabel;
import com.googlecode.d2j.node.insn.BaseSwitchStmtNode;
import com.googlecode.d2j.node.insn.DexStmtNode;
import com.googlecode.d2j.node.insn.JumpStmtNode;
import com.googlecode.d2j.node.insn.DexLabelStmtNode;
import com.googlecode.d2j.visitors.DexCodeVisitor;

public class BasicBlock {
	private int id;
	public List<DexStmtNode> insn;
	public Set<DexLabel> sucLabels;

	public BasicBlock(int id) {
		this.setId(id);
		insn = new ArrayList<DexStmtNode>();
		sucLabels = new HashSet<DexLabel>();
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
