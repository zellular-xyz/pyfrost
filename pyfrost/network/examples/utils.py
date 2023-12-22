from typing import List, Dict
import random


def get_new_random_subset(dictionary: Dict, seed: int, subset_size: int) -> Dict:
    random.seed(seed)
    items = list(dictionary.items())
    if subset_size > len(items):
        raise ValueError(
            "Subset size cannot be greater than the length of the dictionary.")
    random_subset = random.sample(items, subset_size)
    random_subset_dict = dict(random_subset)
    return random_subset_dict
