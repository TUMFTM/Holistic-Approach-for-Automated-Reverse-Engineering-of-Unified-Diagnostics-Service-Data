The following paragraphs are mostly inspired by the blog post "Hypermodern Python" by Claudio Jolowicz ([link](https://cjolowicz.github.io/posts/hypermodern-python-01-setup/)).

### Packaging and Managing Dependencies with `poetry`

For packaging and managing dependencies the tool `poetry` is used. `poetry` is a modern tool that improves upon the older `setuptools` (or even older `disutils`) and allows managing and installing dependencies in separate virtual environments. All the configuration information needed is stored in the required standardized `pyproject.toml` (no need for older `setup.py`, `setup.cfg` or `requirements.txt` files). Information on how to install `poetry` as well as a detailed documentation can be found [here](https://python-poetry.org/docs/#installation).

#### Setting Up an Environment

To create a virtual environment for local development in an existing project (including installing all the dependencies) run:

```bash
poetry install
```

If the base folder contains a `poetry.lock` file, `poetry` installs the dependencies as described in this file (i.e. exactly the version defined in it). If that is not the case, `poetry` reads the `pyproject.toml` file, resolves and installs the dependencies based on the provided constraints (see [here](https://python-poetry.org/docs/master/dependency-specification/) for further details) and then creates a `poetry.lock` file.

By default, `poetry` installs development dependencies (only needed during development, found under `[tool.poetry.group.dev.dependencies]` in the `pyproject.toml` file) as well. To install only the installation dependencies (found under `[tool.poetry.dependencies]` in the `pyproject.toml` file), run the command with the `--no-dev` flag. Moreover, `poetry` by default installs the package itself in editable mode. To avoid installing the package run the command with the flag `--no-root`. Finally, the flag `--sync` can be used to remove installed packages that are no longer present in the `poetry.lock` file.

To activate the virtual environment the command `poetry shell` can be used, which starts a new shell with the activated environment. Alternatively, a specific command can be run inside the environment as follows: `poetry run <command>`.

#### Adding, Removing and Updating Packages

If during development a new package is required, it can be added to the environment (and automatically to the `pyproject.toml` and `poetry.lock` files) by running the command

```bash
poetry add <package>
```

Version constraints can be added following the package's name (e.g. `pytest@^6.2.5`). To add the package as a development dependency use the flag `-G dev`. Similarly, the command `poetry remove` can be used to uninstall and remove packages from the `pyproject.toml` and `poetry.lock` files.

The `poetry.lock` file (when present in the repository) ensures that all developers are using the exact same versions for all dependencies. However, the installed dependencies and therefore also the `poetry.lock` file should be updated regularly. To do this the following command can be used.

```bash
poetry update <package>
```

Version constraints can be provided in this case as well. If no package name is provided, all packages are updated according to the constraints in the `pyproject.toml` file.

#### Package Directory Structure

The `poetry` package expects the standardized Python directory structure to be used. In our case this looks as follows.

```text
revcan
├── pyproject.toml
├── poetry.lock
├── README.md
├── CONTRIBUTING.md
└── revcan
    └── ...
```

The base folder only contains configuration files, in particular the `pyproject.toml` and the `poetry.lock` files, and other descriptive files, such as the `README.md` and this `CONTRIBUTING.md` file.

The source code can be found in a directory with the same name as the repository. In some cases it might make sense to reorganize part of the code in subdirectories. This code is then saved in subdirectories of the main source directory (e.g. `revcan/reverse_engineering`).

If a directory is a Python package or subpackage, it should contain an `__init__.py` file. This file is read and executed automatically when the (sub-)package is imported. This file is empty by default, however it might e.g. contain instructions to initialize a logger or import components of subpackages.

Other code (e.g. `experiments`), build files, data, etc. are stored in different directories next to the source code.