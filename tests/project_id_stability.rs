use interenv::compute_project_id;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_project_id_stability_and_collision_resistance() {
    let temp_root = TempDir::new().unwrap();
    let original_dir = temp_root.path().join("my-repo-dir-1");
    fs::create_dir_all(&original_dir).unwrap();

    // Create .git/HEAD
    let git_dir = original_dir.join(".git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();

    // Create Cargo.toml
    fs::write(
        original_dir.join("Cargo.toml"),
        "[package]\nname = \"my-awesome-tool\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let (id1, name1) = compute_project_id(&original_dir);
    assert_eq!(name1, "my-awesome-tool");

    // Same repo and folder produces identical, deterministic project_id
    let (id1_repeat, name1_repeat) = compute_project_id(&original_dir);
    assert_eq!(id1, id1_repeat);
    assert_eq!(name1, name1_repeat);

    // Two unrelated projects with identical git/manifest in different folders
    // MUST NOT have identical project_id (M-9 folder collision prevention)
    let different_dir = temp_root.path().join("different-folder-dir-2");
    fs::create_dir_all(&different_dir).unwrap();
    let git_dir2 = different_dir.join(".git");
    fs::create_dir_all(&git_dir2).unwrap();
    fs::write(git_dir2.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    fs::write(
        different_dir.join("Cargo.toml"),
        "[package]\nname = \"my-awesome-tool\"\nversion = \"1.0.0\"\n",
    )
    .unwrap();

    let (id2, name2) = compute_project_id(&different_dir);
    assert_eq!(name2, "my-awesome-tool");
    assert_ne!(
        id1, id2,
        "Distinct folders with identical manifests must not collide (M-9)"
    );
}
