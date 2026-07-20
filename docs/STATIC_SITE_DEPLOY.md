# Reusable static-site deployment

The static-site reusable is designed for a one-shot Compose builder that writes assets to a named volume selected through `STATIC_VOLUME_NAME`.

```json
{
  "version": 1,
  "service_name": "marketing-site",
  "source_path": ".",
  "allowed_root": "/opt/optimizr",
  "deploy_root": "/opt/optimizr/optimizr-marketing-site",
  "compose_file": "docker-compose.yml",
  "builder_service": "builder",
  "static_volume": "optimizr-marketing-site_static_files",
  "output_mount_path": "/output",
  "required_outputs": ["index.html", "assets"]
}
```

The builder image must contain POSIX-compatible `test`, `find`, and `cp` entrypoints. The Compose service must mount `${STATIC_VOLUME_NAME}` at `output_mount_path`.

Deployment sequence:

1. copy the repository source to a confined candidate directory;
2. build and run the builder against a candidate volume;
3. verify every required output;
4. copy the stable volume to a rollback volume;
5. replace stable contents with the candidate and verify again;
6. atomically rename the candidate source directory into the deploy path;
7. restore the stable volume automatically if promotion fails.

The workflow requires an exact SHA, protected environment and trusted self-hosted runner. It accepts no command strings or secrets.
