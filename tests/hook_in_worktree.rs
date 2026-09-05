use interenv::git::hook::{find_git_dir, install_pre_commit_hook};
use std::fs;
use std::process::Command;
use tempfile::TempDir;

#[test]
fn test_hook_in_git_worktree() {
    let temp_root = TempDir::new().unwrap();
    let main_repo = temp_root.path().join("main_repo");
    fs::create_dir_all(&main_repo).unwrap();

    // 1. Initialize main git repo
    let init_status = Command::new("git")
        .args(["init", "-b", "main"])
        .current_dir(&main_repo)
        .status();

    // Skip if git is not available in environment
    if init_status.is_err() || !init_status.unwrap().success() {
        return;
    }

    let _ = Command::new("git")
        .args(["config", "user.name", "Test User"])
        .current_dir(&main_repo)
        .status();
    let _ = Command::new("git")
        .args(["config", "user.email", "test@example.com"])
        .current_dir(&main_repo)
        .status();

    // Create initial commit
    fs::write(main_repo.join("README.md"), "# Test Repo\n").unwrap();
    let _ = Command::new("git")
        .args(["add", "."])
        .current_dir(&main_repo)
        .status();
    let _ = Command::new("git")
        .args(["commit", "-m", "initial commit"])
        .current_dir(&main_repo)
        .status();

    // 2. Add git worktree
    let worktree_dir = temp_root.path().join("worktree_repo");
    let wt_status = Command::new("git")
        .args([
            "worktree",
            "add",
            "-b",
            "feature",
            worktree_dir.to_str().unwrap(),
        ])
        .current_dir(&main_repo)
        .status();

    if wt_status.is_ok() && wt_status.unwrap().success() {
        // Assert find_git_dir succeeds inside worktree
        let resolved = find_git_dir(&worktree_dir);
        assert!(
            resolved.is_some(),
            "Must resolve git directory inside worktree"
        );

        // Install hook
        let install_res = install_pre_commit_hook(&resolved.unwrap());
        assert!(
            install_res.is_ok(),
            "Must install pre-commit hook in worktree"
        );
    }
}
