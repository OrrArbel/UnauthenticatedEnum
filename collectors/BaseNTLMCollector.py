import abc

from collectors.CollectorOutput import CollectorOutput
from utils.utils import is_port_open


class BaseNTLMCollector(abc.ABC):
    def __init__(self, targets: list[str]):
        self.targets: list[str] = targets

    @property
    @abc.abstractmethod
    def port(self) -> int:
        pass

    @property
    @abc.abstractmethod
    def name(self) -> str:
        pass

    @abc.abstractmethod
    def collect_data(self, target: str) -> CollectorOutput | None:
        pass

    def run(self) -> list[CollectorOutput]:
        results = []
        for target in self.targets:
            print(
                f"Collecting data from {target} over {self.name} using port {self.port}"
            )
            if not is_port_open(target, self.port):
                print(f"{target}:{self.port} is unreachable. Skipping")
                continue

            collector_output: CollectorOutput = self.collect_data(target)
            if not collector_output:
                print(f"No collector_output collected from {target}")
                continue
            collector_output.collector = self.name
            collector_output.target = target
            results.append(collector_output)
        return results

