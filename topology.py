# to reload module:
# import imp
# imp.reload(module)
import sys
import logging
# change logging level from INFO to DEBUG to print debugging logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(funcName)s - %(lineno)d - %(message)s')

start_node = 52
end_node = 29


class Node:
    def __init__(self, new_id):
        self.id = new_id
        self.neighbours = {}  # { node: weight }

        self.visited = False
        self.distance = sys.maxsize  # value: 9223372036854775807, int
        self.previous = None
        self.hop = 0

    def __str__(self):
        return "Node {} - neighbours: {}".format(self.id, [x.id for x in self.neighbours])

    def __repr__(self):
        return "Node {}: distance = {}, hop = {}".format(self.id, self.distance, self.hop)

    def add_neighbour(self, node, weight):
        self.neighbours[node] = weight

    def get_all_neighbours(self):
        return self.neighbours.keys()

    def get_weight(self, neighbour_node):
        return self.neighbours[neighbour_node]


class Graph:
    def __init__(self):
        self.num_nodes = 0
        self.nodes_dict = {}  # { id: node }

    def __iter__(self):
        return iter(self.nodes_dict.values())  # nodes

    def add_node(self, node_id):
        self.num_nodes += 1
        self.nodes_dict[node_id] = Node(node_id)

    def get_node(self, node_id):
        return self.nodes_dict.get(node_id)

    def add_edge(self, start, end, weight):
        if start not in self.nodes_dict:
            self.add_node(start)
        if end not in self.nodes_dict:
            self.add_node(end)

        self.nodes_dict[start].add_neighbour(self.nodes_dict[end], weight)
        self.nodes_dict[end].add_neighbour(self.nodes_dict[start], weight)

    def get_all_nodes_ids(self):
        return self.nodes_dict.keys()


def construct_path(destination, path):
    if destination.previous:
        path.append(destination.previous.id)

        construct_path(destination.previous, path)

    return


def process_input(input_file, with_weights=True):
    g = Graph()
    f = open(input_file, 'r')

    x = f.readline().strip().split()
    node_count, link_count = int(x[0]), int(x[1])

    for i in range(link_count):
        x = list(map(int, f.readline().strip().split()))
        if with_weights:
            g.add_edge(x[0], x[1], x[2])
        else:
            g.add_edge(x[0], x[1], 1)  # set all weights to 1

    f.close()

    return g


def dijkstra(graph, start):
    # start from the source node, set the distance to itself to 0
    start.distance = 0
    start.hop = -1

    # sort unvisited list of nodes based on distance in descending order
    unvisited = sorted([node for node in graph], key=lambda node: node.distance, reverse=True)

    while unvisited:  # while unvisited list is non-empty
        current = unvisited.pop()  # the node with smallest distance
        current.visited = True
        current.hop += 1

        for node in current.get_all_neighbours():
            if not node.visited:
                new_dist = current.distance + current.get_weight(node)
                if new_dist < node.distance:
                    node.distance = new_dist
                    node.previous = current
                    node.hop = current.hop

        unvisited = sorted(unvisited, key=lambda node: node.distance, reverse=True)

    return


def find_all_min_hop_paths(graph, end, min_hop):

    def find_paths(graph, end, min_hop, path, all):
        if min_hop == 0:
            path.append(end.id)
            all.append(path.copy())
            path.clear()
            return

        for node in end.get_all_neighbours():
            if node.distance == min_hop-1:
                path.append(end.id)
                find_paths(graph, node, min_hop-1, path, all_paths)

    path = []
    all_paths = []

    find_paths(graph, end, min_hop, path, all_paths)

    return all_paths


def find_cost(graph_w, path):
    cost = 0

    for i in range(len(path)-1):
        cost += graph_w.get_node(path[i]).get_weight(graph_w.get_node(path[i+1]))

    return cost


def main():
    input_file = "./network-topology.txt"
    # input_file = "./sample_topology.txt"

    gw = process_input(input_file, True)   # graph with weights
    g1 = process_input(input_file, False)  # graph without weights (set all weights to 1)

    logging.info("Total no. of nodes connected = {}".format(gw.num_nodes))

    # process the graph with weights
    start_w = gw.get_node(start_node)
    end_w = gw.get_node(end_node)

    dijkstra(gw, start_w)

    path_w = [end_w.id]
    construct_path(end_w, path_w)

    print("With Weights {} --> {}: Path = {}, Hop = {}, Distance = {}"
          .format(start_w.id, end_w.id, path_w, len(path_w) - 1, end_w.distance))
    # With Weights 52 --> 29: Path = [29, 85, 758, 491, 957, 774, 206, 52], Hop = 7, Distance = 24

    # process the graph without weights
    start_1 = g1.get_node(start_node)
    end_1 = g1.get_node(end_node)

    dijkstra(g1, start_1)

    path_1 = [end_1.id]
    construct_path(end_1, path_1)

    print("Without Weights {} --> {} : Path = {}, Hop = {}, Distance = {}"
          .format(start_1.id, end_1.id, path_1, len(path_1) - 1, end_1.distance))
    # Without Weights 52 --> 29 : Path = [29, 337, 34, 52], Hop = 3, Distance = 3

    all_paths = find_all_min_hop_paths(g1, end_1, end_1.distance)
    print("In total {} min-hop paths = {}".format(len(all_paths), all_paths))
    # In total 3 min-hop paths = [[29, 451, 206, 52], [29, 151, 527, 52], [29, 337, 34, 52]]

    # find cost for all min hop paths:
    cost_path = {}
    for path in all_paths:
        cost = find_cost(gw, path)
        cost_path[cost] = path

    print("Cost of all min-hop paths = {}".format(cost_path))
    # Cost of all min-hop paths = {54: [29, 451, 206, 52], 50: [29, 151, 527, 52], 90: [29, 337, 34, 52]}

    min_cost = min(cost_path.keys())
    print("Minimum cost among all min-hop paths = {}, path = {}".format(min_cost, cost_path.get(min_cost)))
    # Minimum cost among all min-hop paths = 50, path = [29, 151, 527, 52]

    return gw, g1


if __name__ == "__main__":
    main()

