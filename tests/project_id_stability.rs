use interenv::compute_project_id;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_project_id_stability_across_rename() {
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

    // Now simulate renaming the directory
    let renamed_dir = temp_root.path().join("renamed-directory-folder-2");
    fs::rename(&original_dir, &renamed_dir).unwrap();

    let (id2, name2) = compute_project_id(&renamed_dir);
    assert_eq!(name2, "my-awesome-tool");

    // The project_id MUST be stable across folder renames
    assert_eq!(
        id1, id2,
        "Project ID changed after folder rename! Expected stability."
    );
}
